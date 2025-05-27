//! [`EvmFactory`] implementation for the EVM in the FPVM environment.

use super::precompiles::OpFpvmPrecompiles;
use crate::oracle::MemoryOracleClient;
use alloy_evm::{Database, EvmEnv, EvmFactory};
use alloy_op_evm::OpEvm;
use op_revm::{
    DefaultOp, OpContext, OpEvm as RevmOpEvm, OpHaltReason, OpSpecId, OpTransaction,
    OpTransactionError,
};
use revm::{
    context::{result::EVMError, Evm as RevmEvm, EvmData, TxEnv},
    handler::instructions::EthInstructions,
    inspector::NoOpInspector,
    Context, Inspector,
};

/// Factory producing [`OpEvm`]s with FPVM-accelerated precompile overrides enabled.
#[derive(Debug, Clone)]
pub struct FpvmOpEvmFactory {
    /// The oracle reader.
    oracle_reader: MemoryOracleClient,
}

impl FpvmOpEvmFactory {
    /// Creates a new [`FpvmOpEvmFactory`].
    pub fn new(oracle_reader: MemoryOracleClient) -> Self {
        Self { oracle_reader }
    }
}

impl EvmFactory for FpvmOpEvmFactory {
    type Evm<DB: Database, I: Inspector<OpContext<DB>>> = OpEvm<DB, I, OpFpvmPrecompiles>;
    type Context<DB: Database> = OpContext<DB>;
    type Tx = OpTransaction<TxEnv>;
    type Error<DBError: core::error::Error + Send + Sync + 'static> =
        EVMError<DBError, OpTransactionError>;
    type HaltReason = OpHaltReason;
    type Spec = OpSpecId;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv<OpSpecId>,
    ) -> Self::Evm<DB, NoOpInspector> {
        let spec_id = *input.spec_id();
        let ctx = Context::op()
            .with_db(db)
            .with_block(input.block_env)
            .with_cfg(input.cfg_env);
        let revm_evm = RevmOpEvm(RevmEvm {
            data: EvmData {
                ctx,
                inspector: NoOpInspector {},
            },
            instruction: EthInstructions::new_mainnet(),
            precompiles: OpFpvmPrecompiles::new_with_spec(spec_id, self.oracle_reader.clone()),
        });

        OpEvm::new(revm_evm, false)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<OpSpecId>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let spec_id = *input.spec_id();
        let ctx = Context::op()
            .with_db(db)
            .with_block(input.block_env)
            .with_cfg(input.cfg_env);
        let revm_evm = RevmOpEvm(RevmEvm {
            data: EvmData { ctx, inspector },
            instruction: EthInstructions::new_mainnet(),
            precompiles: OpFpvmPrecompiles::new_with_spec(spec_id, self.oracle_reader.clone()),
        });

        OpEvm::new(revm_evm, true)
    }
}
