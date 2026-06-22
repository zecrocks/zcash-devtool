//! The network parameters the wallet operates against.
//!
//! [`zcash_protocol::consensus::Network`] only models mainnet and testnet, where
//! NU6.3 (Ironwood) is not scheduled (its activation height is `None`). To fund
//! and exercise Ironwood we need a network on which NU6.3 *is* active, which is
//! what [`LocalNetwork`] (regtest / local consensus) provides. This wrapper lets
//! the rest of the tool stay generic over [`consensus::Parameters`] while
//! supporting both the production networks and a regtest network.

use zcash_protocol::{
    consensus::{self, BlockHeight, NetworkType, NetworkUpgrade, Parameters},
    local_consensus::LocalNetwork,
};

/// The regtest activation heights.
///
/// NOTE: these heights are hardcoded specifically for the **zecd Ironwood
/// regtest harness**. They are not a general-purpose regtest schedule; they
/// exist so that this funder, zebra, and zecd all agree within that harness.
///
/// They MUST stay identical to the activation schedule the other components in
/// that harness use — zebra's `configured_activation_heights` and zecd's
/// `regtest()` — or the consensus branch IDs (and therefore transaction
/// validity) diverge and transactions get rejected. The agreed harness schedule
/// is:
///
/// - everything through NU5 and NU6: height 1
/// - NU6.1 and NU6.2: height 4
/// - NU6.3 (Ironwood): height 8
///
/// If the harness changes any of these (e.g. zebra's `nu6_3` height), update the
/// matching value below in lockstep.
///
/// The point of activating NU6.3 is that [`Parameters::is_nu_active`] returns
/// `true` for it, which is what causes the high-level transaction-construction
/// path (`propose_transfer` + `create_proposed_transactions`, i.e. `wallet
/// send`) to emit Ironwood (V6) outputs to the recipient once the target height
/// is at or above the NU6.3 activation height.
pub(crate) const fn regtest_params() -> LocalNetwork {
    // Heights fixed to match the zecd regtest harness (zebra + zecd + this tool).
    let h1 = Some(BlockHeight::from_u32(1));
    let h4 = Some(BlockHeight::from_u32(4));
    let h8 = Some(BlockHeight::from_u32(8));
    LocalNetwork {
        overwinter: h1,
        sapling: h1,
        blossom: h1,
        heartwood: h1,
        canopy: h1,
        nu5: h1,
        nu6: h1,
        nu6_1: h4,
        nu6_2: h4,
        #[cfg(zcash_unstable = "nu6.3")]
        nu6_3: h8,
    }
}

/// The network the wallet operates against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Network {
    /// A production network (mainnet or testnet).
    Consensus(consensus::Network),
    /// A regtest / local-consensus network whose activation heights match the
    /// zecd Ironwood regtest harness (see [`regtest_params`]).
    Regtest(LocalNetwork),
}

impl Network {
    /// Returns the regtest network for the zecd Ironwood harness (see
    /// [`regtest_params`] for the activation schedule).
    pub(crate) const fn regtest() -> Self {
        Network::Regtest(regtest_params())
    }
}

impl Parameters for Network {
    fn network_type(&self) -> NetworkType {
        match self {
            Network::Consensus(params) => params.network_type(),
            Network::Regtest(params) => params.network_type(),
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            Network::Consensus(params) => params.activation_height(nu),
            Network::Regtest(params) => params.activation_height(nu),
        }
    }
}
