use sp1_derive::AlignedBorrow;
use super::*;
use sp1_core::utils::{bytes32, range};

#[derive(AlignedBorrow, Clone, Debug)]
#[repr(C)]
pub struct PoseidonCols<T> {
    // Execution context
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub nonce: T,
    pub pc: T,
    
    // Round tracking
    pub round_ctr: T,
    pub is_full_round: T,
    
    // State elements
    pub state: [T; WIDTH],
    pub next_state: [T; WIDTH],
    
    // Round internals
    pub round_constants: [T; WIDTH],
    pub ark_state: [T; WIDTH],     // After adding round constants
    pub sbox_state: [T; WIDTH],    // After S-box layer
    pub mix_state: [T; WIDTH],     // After mixing layer
    
    // Memory access
    pub input_ptr: T,
    pub output_ptr: T,
    pub is_input_access: T,
    pub is_output_access: T,
    
    // Memory data
    pub mem_value: [T; 32],        // For 256-bit field elements
    pub mem_addr: T,
    pub mem_rw_flag: T,
    
    // Intermediate computation values
    pub temp_1: T,                 // For storing intermediate values
    pub temp_2: T,                 // during complex computations
    
    // Lookup flags
    pub is_arithmetic: T,          // For arithmetic operations
    pub is_memory: T,             // For memory operations
    pub is_binary: T,             // For binary operations
}

impl<T: Default> Default for PoseidonCols<T> {
    fn default() -> Self {
        Self {
            is_real: T::default(),
            shard: T::default(),
            clk: T::default(),
            nonce: T::default(),
            pc: T::default(),
            round_ctr: T::default(),
            is_full_round: T::default(),
            state: [T::default(); WIDTH],
            next_state: [T::default(); WIDTH],
            round_constants: [T::default(); WIDTH],
            ark_state: [T::default(); WIDTH],
            sbox_state: [T::default(); WIDTH],
            mix_state: [T::default(); WIDTH],
            input_ptr: T::default(),
            output_ptr: T::default(),
            is_input_access: T::default(),
            is_output_access: T::default(),
            mem_value: [T::default(); 32],
            mem_addr: T::default(),
            mem_rw_flag: T::default(),
            temp_1: T::default(),
            temp_2: T::default(),
            is_arithmetic: T::default(),
            is_memory: T::default(),
            is_binary: T::default(),
        }
    }
}

impl<T> PoseidonCols<T> {
    pub fn set_execution_context(&mut self, is_real: T, shard: T, clk: T, nonce: T) 
    where T: Clone {
        self.is_real = is_real;
        self.shard = shard;
        self.clk = clk;
        self.nonce = nonce;
    }

    pub fn set_round_context(&mut self, round: T, is_full: T)
    where T: Clone {
        self.round_ctr = round;
        self.is_full_round = is_full;
    }

    pub fn set_memory_access(&mut self, addr: T, is_write: T)
    where T: Clone {
        self.mem_addr = addr;
        self.mem_rw_flag = is_write;
        self.is_memory = T::default(); // Set to true for memory operations
    }
}