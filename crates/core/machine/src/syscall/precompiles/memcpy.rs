
pub fn memory_copy_32<F: PrimeField32>(
    local_chip: &MemoryLocalChip,
    src: *const Fr,
    dst: *mut Fr
) {
 
    let event = MemoryLocalEvent {
        addr: src as u32,
        initial_mem_access: MemoryRecord {
            shard: current_shard,
            timestamp: current_clk,
            value: unsafe { *src }
        },
        final_mem_access: MemoryRecord {
            shard: current_shard, 
            timestamp: current_clk + 1,
            value: unsafe { *src }
        }
    };
    
    local_chip.process_memory_event(event);
}


pub fn memory_copy_64<F: PrimeField32>(
    local_chip: &MemoryLocalChip,
    src: *const Fr,
    dst: *mut Fr
) {
    
    let low_event = MemoryLocalEvent {
        addr: src as u32,
        initial_mem_access: MemoryRecord {
            shard: current_shard,
            timestamp: current_clk,
            value: unsafe { *src }
        },
        final_mem_access: MemoryRecord {
            shard: current_shard,
            timestamp: current_clk + 1, 
            value: unsafe { *src }
        }
    };

    let high_event = MemoryLocalEvent {
        addr: (src as u32) + 4,
        initial_mem_access: MemoryRecord {
            shard: current_shard,
            timestamp: current_clk,
            value: unsafe { *src.offset(1) }
        },
        final_mem_access: MemoryRecord {
            shard: current_shard,
            timestamp: current_clk + 1,
            value: unsafe { *src.offset(1) }
        }
    };

    local_chip.process_memory_event(low_event);
    local_chip.process_memory_event(high_event); 
}