use std::time::Duration;

use anyhow::{Context, Result};
use futures::{StreamExt, channel::mpsc};
use hopr_api::{
    node::{
        DepositUpdated, PixAddressId, PixDepositAddressReceived, PixDepositDataRequest, PixEvent, PixNewDepositAddress,
        PixPrivateKeyRecovered,
    },
    types::primitive::prelude::{Address, HoprBalance, XDaiBalance},
};
use hopr_strategy::pix::{
    secp256k1::{DEPOSIT_MARKER_PAYLOAD, NonAnonymousDepositPoolConfig},
    strategy::{PixStrategy, PixStrategyConfig},
};
use hopr_strategy_integration_tests::{
    fixtures::{
        IntegrationFixture, PixScenarioOpts, deposit_data_channel, deposit_secret, integration_fixture as fixture,
        pix_address_id, pool_deposit_data,
    },
    task::StrategyTask,
};
use rstest::rstest;

fn pix_config(price_per_byte: HoprBalance, max_ssa_allocation: HoprBalance) -> PixStrategyConfig {
    PixStrategyConfig {
        price_per_byte,
        max_ssa_allocation,
        pix_recovery_db_path: None,
        pix_recovery_password_env: None,
        deposit_buffer_period: Duration::ZERO,
        withdrawal_buffer_period: Duration::ZERO,
    }
}

/// Pool config with the gas top-up disabled: `fund_sweep_gas` then short-circuits, so a sweep is a
/// single transaction and the scenario does not have to keep the Safe stocked with xDai.
fn pool_config(max_deposit_tracking_time: Duration) -> NonAnonymousDepositPoolConfig {
    NonAnonymousDepositPoolConfig {
        max_deposit_tracking_time,
        gas_xdai_per_sweep: XDaiBalance::zero(),
        ..Default::default()
    }
}

/// Creates the notification channel the Exit side hands to the strategy through
/// `PixDepositAddressReceived::deposit_updated`.
fn deposit_notifier() -> (DepositUpdated, mpsc::Receiver<(PixAddressId, HoprBalance)>) {
    mpsc::channel(1)
}

/// Happy path, Entry side: a `NewDepositAddress` event makes the strategy transfer
/// `price_per_byte * quota` to the deposit address.
///
/// The strategy is purely event-driven — there is no periodic scan to disable — so
/// the injected event is by construction the only possible trigger.
#[rstest]
#[test_log::test(tokio::test)]
async fn deposits_to_new_deposit_address(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [node, deposit] = fixture.claim_accounts::<2>();

    let scenario = fixture
        .open_pix_scenario(&node, PixScenarioOpts::new(&[deposit.address])?)
        .await?;

    let price_per_byte = HoprBalance::new_base(1u32);
    let quota = 20u64;
    let target = price_per_byte * quota;

    let node_before = scenario.hopr_balance(scenario.node_addr).await?;

    let mut strategy = PixStrategy::new(pix_config(price_per_byte, HoprBalance::new_base(100u32)))
        .build_non_anonymous::<_, Address>(scenario.node.clone(), pool_config(Duration::from_secs(60)))?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    let id = pix_address_id(0x11, 1);
    scenario.inject(PixEvent::NewDepositAddress(PixNewDepositAddress {
        id,
        address: deposit.address.into(),
        quota,
        deposit_data: pool_deposit_data(id),
    }));

    let deposited = scenario
        .await_hopr_balance(
            deposit.address,
            timeouts.action,
            "deposit address funded by strategy",
            |balance| !balance.is_zero(),
        )
        .await
        .context("strategy did not fund the deposit address within the timeout")?;

    assert_eq!(deposited, target);
    assert_eq!(scenario.hopr_balance(scenario.node_addr).await?, node_before - target);

    assert!(!handle.is_finished(), "pix strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// Allocation gate: a quota whose price exceeds `max_ssa_allocation` must not be
/// funded.
///
/// `run()` only logs the per-event error and keeps consuming the stream, so the
/// rejection is unobservable from the outside — absence of a transfer, plus the
/// strategy still running afterwards, is the whole assertion.
#[rstest]
#[test_log::test(tokio::test)]
async fn skips_deposit_exceeding_max_ssa_allocation(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [node, deposit] = fixture.claim_accounts::<2>();

    let scenario = fixture
        .open_pix_scenario(&node, PixScenarioOpts::new(&[deposit.address])?)
        .await?;

    // 10 wxHOPR/byte * 10 bytes = 100 wxHOPR, well over the 50 wxHOPR cap.
    let mut strategy =
        PixStrategy::new(pix_config(HoprBalance::new_base(10u32), HoprBalance::new_base(50u32)))
            .build_non_anonymous::<_, Address>(scenario.node.clone(), pool_config(Duration::from_secs(60)))?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    let id = pix_address_id(0x22, 1);
    scenario.inject(PixEvent::NewDepositAddress(PixNewDepositAddress {
        id,
        address: deposit.address.into(),
        quota: 10,
        deposit_data: pool_deposit_data(id),
    }));

    scenario
        .assert_hopr_balance_never(
            deposit.address,
            timeouts.stable,
            "over-allocated quota must not be funded",
            |balance| !balance.is_zero(),
        )
        .await?;

    assert!(!handle.is_finished(), "pix strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// Happy path, Exit side: a `DepositAddressReceived` event makes the strategy track
/// the deposit address and report the balance on the event's own channel.
///
/// The address is pre-credited with the full target, so `notify_deposit` resolves
/// on its immediate balance check and the assertion does not depend on the poll
/// interval.
#[rstest]
#[test_log::test(tokio::test)]
async fn notifies_when_deposit_arrives(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [node, deposit] = fixture.claim_accounts::<2>();

    let price_per_byte = HoprBalance::new_base(1u32);
    let quota = 30u64;
    let target = price_per_byte * quota;

    let scenario = fixture
        .open_pix_scenario(
            &node,
            PixScenarioOpts::new(&[deposit.address])?.with_deposited(deposit.address, target),
        )
        .await?;

    let mut strategy = PixStrategy::new(pix_config(price_per_byte, HoprBalance::new_base(100u32)))
        .build_non_anonymous::<_, Address>(scenario.node.clone(), pool_config(Duration::from_secs(60)))?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    let id = pix_address_id(0x33, 1);
    let (notifier, mut notifications) = deposit_notifier();
    scenario.inject(PixEvent::DepositAddressReceived(PixDepositAddressReceived {
        id,
        address: deposit.address.into(),
        quota,
        deposit_updated: notifier,
        deposit_data: pool_deposit_data(id),
    }));

    let (notified_id, notified_balance) = tokio::time::timeout(timeouts.action, notifications.next())
        .await
        .context("strategy did not report the deposit within the timeout")?
        .context("deposit notification channel closed without a notification")?;

    assert_eq!(notified_id, id);
    assert_eq!(notified_balance, target);

    assert!(!handle.is_finished(), "pix strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// Happy path, Exit side: a `PrivateKeyRecovered` event makes the strategy sweep the
/// deposit address dry into the node's Safe.
///
/// The destination is not configured directly — it is whatever
/// `build_non_anonymous` captured from `identity().safe_address` — so this also
/// pins down that the node adapter reports the right Safe.
#[rstest]
#[test_log::test(tokio::test)]
async fn sweeps_recovered_deposit_to_safe(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [node, deposit] = fixture.claim_accounts::<2>();

    let deposited = HoprBalance::new_base(40u32);
    let scenario = fixture
        .open_pix_scenario(
            &node,
            PixScenarioOpts::new(&[deposit.address])?.with_deposited(deposit.address, deposited),
        )
        .await?;

    let safe_before = scenario.hopr_balance(scenario.safe_addr).await?;

    let mut strategy =
        PixStrategy::new(pix_config(HoprBalance::new_base(1u32), HoprBalance::new_base(100u32)))
            .build_non_anonymous::<_, Address>(scenario.node.clone(), pool_config(Duration::from_secs(60)))?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    scenario.inject(PixEvent::PrivateKeyRecovered(PixPrivateKeyRecovered {
        id: pix_address_id(0x44, 1),
        secret: deposit_secret(&deposit)?,
    }));

    scenario
        .await_hopr_balance(
            deposit.address,
            timeouts.action,
            "deposit address swept by strategy",
            |balance| balance.is_zero(),
        )
        .await
        .context("strategy did not sweep the deposit address within the timeout")?;

    assert_eq!(
        scenario.hopr_balance(scenario.safe_addr).await?,
        safe_before + deposited
    );

    assert!(!handle.is_finished(), "pix strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// Full round trip through one deposit address: deposit, deposit notification, and
/// withdrawal, driven end to end by a single running strategy.
///
/// Tracking starts while the address is still empty, so the notification has to come
/// from `notify_deposit`'s balance poll rather than its immediate-check fast path.
/// `max_deposit_tracking_time` of 10s gives a 1s poll interval (and up to 1s of
/// phase jitter), comfortably inside the tracking deadline.
///
/// Each step is injected only once the previous one is observable. `run()` handles
/// events one at a time, and the sweep is injected after the notification has already
/// resolved, so the sweep cannot drain the address out from under the tracker.
#[rstest]
#[test_log::test(tokio::test)]
async fn completes_deposit_notification_and_withdrawal_roundtrip(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [node, deposit] = fixture.claim_accounts::<2>();

    let scenario = fixture
        .open_pix_scenario(&node, PixScenarioOpts::new(&[deposit.address])?)
        .await?;

    let price_per_byte = HoprBalance::new_base(1u32);
    let quota = 25u64;
    let target = price_per_byte * quota;
    let max_deposit_tracking_time = Duration::from_secs(10);

    let node_before = scenario.hopr_balance(scenario.node_addr).await?;
    let safe_before = scenario.hopr_balance(scenario.safe_addr).await?;

    let mut strategy = PixStrategy::new(pix_config(price_per_byte, HoprBalance::new_base(100u32)))
        .build_non_anonymous::<_, Address>(scenario.node.clone(), pool_config(max_deposit_tracking_time))?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    let id = pix_address_id(0x55, 1);

    // 1. Exit side starts tracking an address that is still empty.
    let (notifier, mut notifications) = deposit_notifier();
    scenario.inject(PixEvent::DepositAddressReceived(PixDepositAddressReceived {
        id,
        address: deposit.address.into(),
        quota,
        deposit_updated: notifier,
        deposit_data: pool_deposit_data(id),
    }));

    // 2. Entry side funds the very same address.
    scenario.inject(PixEvent::NewDepositAddress(PixNewDepositAddress {
        id,
        address: deposit.address.into(),
        quota,
        deposit_data: pool_deposit_data(id),
    }));

    let deposited = scenario
        .await_hopr_balance(
            deposit.address,
            timeouts.action,
            "deposit address funded by strategy",
            |balance| !balance.is_zero(),
        )
        .await
        .context("strategy did not fund the deposit address within the timeout")?;
    assert_eq!(deposited, target);
    assert_eq!(scenario.hopr_balance(scenario.node_addr).await?, node_before - target);

    // 3. The tracker's poll picks the deposit up and reports it.
    let (notified_id, notified_balance) = tokio::time::timeout(max_deposit_tracking_time, notifications.next())
        .await
        .context("strategy did not report the deposit within the tracking deadline")?
        .context("deposit notification channel closed without a notification")?;
    assert_eq!(notified_id, id);
    assert_eq!(notified_balance, target);

    // 4. The Exit recovers the key and 5. sweeps the deposit into its Safe.
    scenario.inject(PixEvent::PrivateKeyRecovered(PixPrivateKeyRecovered {
        id,
        secret: deposit_secret(&deposit)?,
    }));

    scenario
        .await_hopr_balance(
            deposit.address,
            timeouts.action,
            "deposit address swept by strategy",
            |balance| balance.is_zero(),
        )
        .await
        .context("strategy did not sweep the deposit address within the timeout")?;

    assert_eq!(scenario.hopr_balance(scenario.safe_addr).await?, safe_before + target);

    assert!(!handle.is_finished(), "pix strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}

/// Exit side, step 1 of the PIX flow: the strategy answers a `DepositDataRequest` from its pool.
///
/// This is the only test that drives the request path through the real `run` loop, which is where
/// the answer is produced in a task of its own. Routing is the point — every requested allocation
/// answered, in order — but the contents are checked too: what comes back is what the peer's pool
/// will verify on arrival, so a payload that survives generation and hand-off but not the peer's
/// check would be a failure this test is placed to catch.
#[rstest]
#[test_log::test(tokio::test)]
async fn generates_deposit_data_for_every_requested_allocation(fixture: IntegrationFixture) -> Result<()> {
    let timeouts = fixture.timeouts();
    let [node, deposit] = fixture.claim_accounts::<2>();

    let scenario = fixture
        .open_pix_scenario(&node, PixScenarioOpts::new(&[deposit.address])?)
        .await?;

    let mut strategy =
        PixStrategy::new(pix_config(HoprBalance::new_base(1u32), HoprBalance::new_base(100u32)))
            .build_non_anonymous::<_, Address>(scenario.node.clone(), pool_config(Duration::from_secs(60)))?;
    let handle = StrategyTask::spawn_logged(async move { strategy.run().await });

    let requested = vec![pix_address_id(0x66, 1), pix_address_id(0x66, 2)];
    let (created, mut payloads) = deposit_data_channel();

    scenario.inject(PixEvent::DepositDataRequest(PixDepositDataRequest {
        deposit_ids: requested.clone(),
        deposit_data_created: created,
    }));

    for expected in &requested {
        let payload = tokio::time::timeout(timeouts.action, payloads.next())
            .await
            .context("strategy did not generate deposit data within the timeout")?
            .context("deposit data channel closed before every allocation was answered")?;

        assert_eq!(&payload.id, expected, "payloads must arrive in the order asked");
        assert_eq!(
            &*payload.data, &DEPOSIT_MARKER_PAYLOAD,
            "the payload must be the marker the receiving pool checks for"
        );
    }

    assert!(!handle.is_finished(), "pix strategy exited unexpectedly");
    handle.stop().await;
    Ok(())
}
