use super::*;
use p3_matrix::dense::RowMajorMatrix;

impl PoseidonChip {
    pub fn generate_trace(
        &self,
        input: &[Fr],
    ) -> RowMajorMatrix<Fr> {
        let mut rows = vec![];
        let mut state = [Fr::zero(); WIDTH];
        
        // Initialize state with input
        for (i, val) in input.iter().enumerate().take(WIDTH) {
            state[i] = *val;
        }

        // Generate rows for each round
        for round in 0..FULL_ROUNDS + PARTIAL_ROUNDS {
            let is_full = round < FULL_ROUNDS/2 || 
                         round >= FULL_ROUNDS/2 + PARTIAL_ROUNDS;
            
            let mut row = vec![Fr::zero(); self.width()];
            let cols: &mut PoseidonCols<Fr> = row.as_mut_slice().borrow_mut();
            
            // Set execution context
            cols.set_execution_context(
                Fr::one(),                              // is_real
                Fr::from_canonical_u64(0),              // shard
                Fr::from_canonical_u64(round as u64),   // clk
                Fr::from_canonical_u64(round as u64),   // nonce
            );
            
            // Set round context
            cols.set_round_context(
                Fr::from_canonical_u64(round as u64),
                if is_full { Fr::one() } else { Fr::zero() },
            );
            
            // Current state
            cols.state.copy_from_slice(&state);
            
            // Round constants
            cols.round_constants.copy_from_slice(&ROUND_CONSTANTS[round]);
            
            // 1. Add round constants (ARK)
            let mut ark_state = state;
            for i in 0..WIDTH {
                ark_state[i] += ROUND_CONSTANTS[round][i];
            }
            cols.ark_state.copy_from_slice(&ark_state);
            
            // 2. S-box layer
            let mut sbox_state = ark_state;
            if is_full {
                for i in 0..WIDTH {
                    let square = sbox_state[i].square();
                    let quad = square.square();
                    sbox_state[i] = quad * sbox_state[i];
                    
                    // Store intermediate values
                    if i == 0 {
                        cols.temp_1 = square;
                        cols.temp_2 = quad;
                    }
                }
            } else {
                let square = sbox_state[0].square();
                let quad = square.square();
                sbox_state[0] = quad * sbox_state[0];
                cols.temp_1 = square;
                cols.temp_2 = quad;
            }
            cols.sbox_state.copy_from_slice(&sbox_state);
            
            // 3. Mix layer (MDS)
            let mut mix_state = [Fr::zero(); WIDTH];
            for i in 0..WIDTH {
                for j in 0..WIDTH {
                    mix_state[i] += sbox_state[j] * POSEIDON_MDS[i][j];
                }
            }
            cols.mix_state.copy_from_slice(&mix_state);
            
            // Update state
            state = mix_state;
            cols.next_state.copy_from_slice(&state);
            
            // Set computation flags
            cols.is_arithmetic = Fr::one();
            cols.is_memory = Fr::zero();
            cols.is_binary = Fr::zero();
            
            rows.push(row);
        }
        
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            self.width()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_generation() {
        let chip = PoseidonChip::new();
        let input = [Fr::one(), Fr::zero(), Fr::zero()];
        let trace = chip.generate_trace(&input);
        
        assert_eq!(trace.height(), FULL_ROUNDS + PARTIAL_ROUNDS);
        
        // Verify first row
        let first_row: &PoseidonCols<Fr> = trace.row_slice(0).borrow();
        assert_eq!(first_row.is_real, Fr::one());
        assert_eq!(first_row.state[0], Fr::one());
        assert_eq!(first_row.state[1], Fr::zero());
        assert_eq!(first_row.state[2], Fr::zero());
        
        // Verify final row contains valid hash
        let final_row: &PoseidonCols<Fr> = trace.row_slice(trace.height()-1).borrow();
        assert!(final_row.state[0] != Fr::zero()); // Hash should not be zero
    }
}