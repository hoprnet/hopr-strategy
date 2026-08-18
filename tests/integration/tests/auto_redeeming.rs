use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use hopr_api::{
    chain::ChainValues,
    types::{
        crypto::prelude::{ChainKeypair, HalfKey, Hash, Keypair, Response},
        internal::prelude::{RedeemableTicket, TicketBuilder, WinningProbability},
        primitive::prelude::{Address, HoprBalance},
    },
};
use hopr_strategy::{
    auto_redeeming::{AutoRedeemingStrategy, AutoRedeemingStrategyConfig},
    testing::{LiveTicketManager, TicketNode},
};
use hopr_strategy_integration_tests::{
    TestAccount,
    fixtures::{
        ChannelParty, ChannelScenario, IntegrationFixture, ScenarioOpts, assert_channel_never, await_channel_where,
        integration_fixture as fixture,
    },
    strategy_node::{NodeConnector, node_chain_keypair},
    task::StrategyTask,
};
use rstest::rstest;

/// Builds a signed, redeemable `ALWAYS`-winning ticket for the `issuer -> redeemer`
/// channel at the given index/epoch, mirroring what a node would acknowledge.
#[allow(clippy::too_many_arguments)]
fn build_redeemable_ticket(
    issuer_key: &ChainKeypair,
    redeemer_key: &ChainKeypair,
    redeemer_addr: Address,
    channel_dst: &Hash,
    amount: HoprBalance,
    index: u64,
    channel_epoch: u32,
) -> Result<RedeemableTicket> {
    let issuer_half = HalfKey::try_from(issuer_key.secret().as_ref())?;
    let redeemer_half = HalfKey::try_from(redeemer_key.secret().as_ref())?;
    let response = Response::from_half_keys(&issuer_half, &redeemer_half)?;
    Ok(TicketBuilder::default()
        .counterparty(redeemer_addr)
        .amount(amount.amount())
        .index(index)
        .win_prob(WinningProbability::ALWAYS)
        .channel_epoch(channel_epoch)
        .challenge(response.to_challenge()?)
        .build_signed(issuer_key, channel_dst)?
        .into_acknowledged(response)
        .into_redeemable(redeemer_key, channel_dst)?)
}

/// Onboards issuer + redeemer, opens a 10 wxHOPR `issuer -> redeemer` channel with
/// the node connected as the redeemer, and queues a single 2 wxHOPR winning ticket.
/// Returns the scenario, the redeemer node, and the queued ticket amount.
async fn ticket_scenario(
    fixture: &IntegrationFixture,
    issuer: &TestAccount,
    redeemer: &TestAccount,
) -> Result<(ChannelScenario, Arc<TicketNode<Arc<NodeConnector>>>, HoprBalance)> {
    let scenario = fixture
        .open_channel_scenario(
            issuer,
            redeemer,
            ScenarioOpts {
                connect_as: ChannelParty::Destination,
                ..ScenarioOpts::new("10 wxHOPR".parse()?)?
            },
        )
        .await?;

    let issuer_key = node_chain_keypair(issuer.secret_bytes())?;
    let redeemer_key = node_chain_keypair(redeemer.secret_bytes())?;
    let channel_dst = scenario.connector.domain_separators().await?.channel;
    let ticket_amount: HoprBalance = "2 wxHOPR".parse()?;
    let ticket = build_redeemable_ticket(
        &issuer_key,
        &redeemer_key,
        scenario.destination_addr,
        &channel_dst,
        ticket_amount,
        scenario.initial.ticket_index,
        scenario.initial.channel_epoch,
    )?;
    let node = Arc::new(TicketNode::new(
        scenario.connector.clone(),
        LiveTicketManager::with_ticket(ticket),
    ));
    Ok((scenario, node, ticket_amount))
}

/// Happy path: the periodic scan redeems a queued winning ticket in an open
/// incoming channel (`redeem_on_winning = false`, no value floor).
#[rstest]
#[test_log::test(tokio::test)]
async fn redeems_queued_ticket(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [issuer, redeemer] = fixture.claim_accounts::<2>();
    let (scenario, node, ticket_amount) = ticket_scenario(&fixture, &issuer, &redeemer).await?;
    let initial_index = scenario.initial.ticket_index;
    let initial_balance = scenario.initial.balance;

    let mut strategy = AutoRedeemingStrategy::new(
        AutoRedeemingStrategyConfig {
            minimum_redeem_ticket_value: HoprBalance::zero(),
            redeem_on_winning: false,
            ..Default::default()
        },
        Duration::from_secs(3600),
    )
    .build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    let redeemed = await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "ticket redeemed by strategy",
        move |channel| channel.ticket_index > initial_index,
    )
    .await?;
    assert_eq!(redeemed.balance, initial_balance - ticket_amount);
    assert!(!handle.is_finished(), "auto-redeeming strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// `redeem_all_on_close`: a queued ticket must be redeemed when the incoming
/// channel transitions to `PendingToClose`. `redeem_on_winning = true` disables
/// the periodic scan so the closure event is the *only* possible trigger,
/// isolating the on-close path.
#[rstest]
#[test_log::test(tokio::test)]
async fn redeems_all_tickets_on_channel_closure(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [issuer, redeemer] = fixture.claim_accounts::<2>();
    let (scenario, node, ticket_amount) = ticket_scenario(&fixture, &issuer, &redeemer).await?;
    let initial_index = scenario.initial.ticket_index;
    let initial_balance = scenario.initial.balance;

    let mut strategy = AutoRedeemingStrategy::new(
        AutoRedeemingStrategyConfig {
            minimum_redeem_ticket_value: HoprBalance::zero(),
            redeem_all_on_close: true,
            // Disable the periodic scan so only the on-close event can redeem.
            redeem_on_winning: true,
        },
        Duration::from_secs(3600),
    )
    .build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // Trigger the incoming-channel closure; the redeemer observes it as a
    // ChannelClosureInitiated event and should redeem the queued ticket.
    scenario
        .initiate_closure()
        .await
        .context("failed to initiate channel closure")?;

    let redeemed = await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "ticket redeemed on channel closure",
        move |channel| channel.ticket_index > initial_index,
    )
    .await?;
    assert_eq!(redeemed.balance, initial_balance - ticket_amount);
    assert!(!handle.is_finished(), "auto-redeeming strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// `minimum_redeem_ticket_value` gate: a ticket worth less than the configured
/// minimum must never be redeemed — the redemption stream reports `ValueTooLow`
/// and no on-chain transaction is issued, so the channel ticket index stays put.
#[rstest]
#[test_log::test(tokio::test)]
async fn skips_ticket_below_minimum_value(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [issuer, redeemer] = fixture.claim_accounts::<2>();
    let (scenario, node, _ticket_amount) = ticket_scenario(&fixture, &issuer, &redeemer).await?;
    let initial_index = scenario.initial.ticket_index;

    let mut strategy = AutoRedeemingStrategy::new(
        AutoRedeemingStrategyConfig {
            // Minimum well above the 2 wxHOPR ticket value.
            minimum_redeem_ticket_value: "5 wxHOPR".parse()?,
            redeem_on_winning: false,
            ..Default::default()
        },
        Duration::from_secs(3600),
    )
    .build(node)?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // The sub-threshold ticket must never be redeemed: ticket index stays put.
    assert_channel_never(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.stable,
        "sub-minimum ticket must not be redeemed",
        move |channel| channel.ticket_index > initial_index,
    )
    .await?;
    assert!(!handle.is_finished(), "auto-redeeming strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// Event-driven path: with `redeem_on_winning = true` the periodic scan is
/// disabled (and the tick is set far in the future), so redemption is triggered
/// *only* by a winning-ticket event arriving on the node's actionable-event
/// stream — the path a live node exercises on ticket acknowledgement.
#[rstest]
#[test_log::test(tokio::test)]
async fn redeems_ticket_on_winning_event(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [issuer, redeemer] = fixture.claim_accounts::<2>();
    let (scenario, node, ticket_amount) = ticket_scenario(&fixture, &issuer, &redeemer).await?;
    let initial_index = scenario.initial.ticket_index;
    let initial_balance = scenario.initial.balance;

    let mut strategy = AutoRedeemingStrategy::new(
        AutoRedeemingStrategyConfig {
            minimum_redeem_ticket_value: HoprBalance::zero(),
            redeem_on_winning: true,
            // On-close redemption disabled so the winning-ticket event is the only trigger.
            redeem_all_on_close: false,
        },
        // Tick far in the future so the periodic scan cannot fire during the test.
        Duration::from_secs(3600),
    )
    .build(node.clone())?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    // Emit the winning-ticket event for the queued ticket. The unbounded channel
    // buffers it, so it is delivered even if the strategy has not subscribed yet.
    node.inject_winning_ticket();

    let redeemed = await_channel_where(
        &scenario.connector,
        scenario.source_addr,
        scenario.destination_addr,
        timeouts.action,
        "ticket redeemed on winning event",
        move |channel| channel.ticket_index > initial_index,
    )
    .await?;
    assert_eq!(redeemed.balance, initial_balance - ticket_amount);
    assert!(!handle.is_finished(), "auto-redeeming strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}
