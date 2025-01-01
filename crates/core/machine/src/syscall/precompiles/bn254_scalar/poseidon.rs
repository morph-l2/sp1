use sp1_core_machine_sys::memory_local::*;
use sp1_core_machine_sys::uint256::*;

#[inline(always)]
pub(crate) fn sbox_inplace(val: &mut U256) {
    let mut a = MaybeUninit::<U256>::uninit();
    
    unsafe {
        let ptr = a.as_mut_ptr();
        // SP1 memcpy
        memory_local_event_to_row_babybear(
            &MemoryLocalEvent::new(val, ptr),
            &mut SingleMemoryLocal::new()
        );
        
        // SP1 uint256
        for _ in 0..4 {
            uint256_mul(ptr, val);
        }
        
        // 
        memory_local_event_to_row_babybear(
            &MemoryLocalEvent::new(ptr, val),
            &mut SingleMemoryLocal::new()
        );
    }
}

#[inline(always)]
pub(crate) fn fill_state(state: &mut MaybeUninit<State>, val: &U256) {
    let ptr = state.as_mut_ptr() as *mut U256;
    for i in 0..T {
        unsafe {
            
            memory_local_event_to_row_babybear(
                &MemoryLocalEvent::new(val, ptr.add(i)),
                &mut SingleMemoryLocal::new()
            );
        }
    }
}

#[inline(always)]
pub(crate) fn set_state(state: &mut State, new_state: &State) {
    unsafe {
       
        for i in 0..3 {
            memory_local_event_to_row_babybear(
                &MemoryLocalEvent::new(&new_state[i], &mut state[i]),
                &mut SingleMemoryLocal::new()
            );
        }
    }
}

#[inline(always)]
pub(crate) fn init_state_with_cap_and_msg<'a>(
    state: &'a mut MaybeUninit<State>,
    cap: &U256,
    msg: &[U256],
) -> &'a mut State {
    static ZERO_TWO: [U256; 2] = [U256::zero(), U256::zero()];

    unsafe {
        let ptr = state.as_mut_ptr() as *mut U256;
        
        
        memory_local_event_to_row_babybear(
            &MemoryLocalEvent::new(cap, ptr),
            &mut SingleMemoryLocal::new()
        );

        match msg.len() {
            0 => {
               
                memory_local_event_to_row_babybear(
                    &MemoryLocalEvent::new(
                        &ZERO_TWO,
                        ptr.add(1)
                    ),
                    &mut SingleMemoryLocal::new()
                );
            }
            1 => {
               
                memory_local_event_to_row_babybear(
                    &MemoryLocalEvent::new(msg.as_ptr(), ptr.add(1)),
                    &mut SingleMemoryLocal::new()
                );
                memory_local_event_to_row_babybear(
                    &MemoryLocalEvent::new(&ZERO_TWO[0], ptr.add(2)),
                    &mut SingleMemoryLocal::new()
                );
            }
            _ => {
               
                memory_local_event_to_row_babybear(
                    &MemoryLocalEvent::new(
                        msg.as_ptr(),
                        ptr.add(1)
                    ),
                    &mut SingleMemoryLocal::new()
                );
            }
        }
        state.assume_init_mut()
    }
}

#[inline(always)]
pub(crate) fn mul_add_assign(dst: &mut U256, a: &U256, b: &U256) {
    unsafe {
    
        let tmp = uint256_mul(a, b);
        *dst = uint256_add(*dst, tmp);
    }
}