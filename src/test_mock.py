import time
from logic.detector import ThresholdEngine
from logic.healer import PolicyHealer


def main():
    """
    Mock Validation Script: Westermo Test System Performance Dataset
    
    This script demonstrates the Stateful Escalation Matrix using a synthetic
    dataset with sustained CPU anomaly to trigger Level 1 -> 2 -> 4 -> 5 escalation.
    """
    
    # Initialization
    engine = ThresholdEngine()
    healer = PolicyHealer()
    
    # CRITICAL OVERRIDE: Set study_duration to 0 to bypass 48-hour calibration
    engine.study_duration = 0
    
    # Mock Dataset: Westermo Test System Performance (minute-by-minute)
    mock_dataset = [
        # Minutes 1-2: Normal baseline data
        {
            "minute": 1,
            "CPU": 35.0,
            "MEMORY": 38.0,
            "STORAGE": 45.0,
            "NETWORK": 12.5,
        },
        {
            "minute": 2,
            "CPU": 36.5,
            "MEMORY": 39.2,
            "STORAGE": 45.1,
            "NETWORK": 13.1,
        },
        # Minutes 3-7: Sustained CPU Anomaly (98-100%)
        {
            "minute": 3,
            "CPU": 98.0,
            "MEMORY": 39.5,
            "STORAGE": 45.2,
            "NETWORK": 12.8,
        },
        {
            "minute": 4,
            "CPU": 99.2,
            "MEMORY": 40.1,
            "STORAGE": 45.3,
            "NETWORK": 13.2,
        },
        {
            "minute": 5,
            "CPU": 99.8,
            "MEMORY": 40.3,
            "STORAGE": 45.4,
            "NETWORK": 12.9,
        },
        {
            "minute": 6,
            "CPU": 100.0,
            "MEMORY": 40.5,
            "STORAGE": 45.5,
            "NETWORK": 13.0,
        },
        {
            "minute": 7,
            "CPU": 99.5,
            "MEMORY": 40.2,
            "STORAGE": 45.6,
            "NETWORK": 13.3,
        },
    ]
    
    print("=" * 80)
    print("WESTERMO TEST SYSTEM: AI-POWERED AUTO-HEALING VALIDATION")
    print("=" * 80)
    print(f"Starting mock validation with {len(mock_dataset)} minute(s) of simulated data...")
    print(f"Thresholds: MIN={engine.MIN_THRESH}%, MAX={engine.MAX_THRESH}%")
    print(f"Study Duration Override: {engine.study_duration} seconds (48-hour calibration bypassed)")
    print("=" * 80)
    print()
    
    # Execution Loop
    for row in mock_dataset:
        minute = row["minute"]
        
        # Print minute header
        print(f"--- Simulated Minute {minute} ---")
        
        # Extract metrics
        state = {
            "CPU": row["CPU"],
            "MEMORY": row["MEMORY"],
            "STORAGE": row["STORAGE"],
            "NETWORK": row["NETWORK"],
        }
        
        # SENSE: Print the data being ingested
        print(f"SENSE: CPU={state['CPU']:.1f}% | MEMORY={state['MEMORY']:.1f}% | STORAGE={state['STORAGE']:.1f}% | NETWORK={state['NETWORK']:.1f}Mbps")
        
        # LEARN: Record data point and update thresholds
        engine.record_data_point(state)
        engine.update_thresholds()
        
        # Display current thresholds
        print(f"THRESHOLDS: CPU={engine.active_thresholds['CPU']:.1f}% | MEMORY={engine.active_thresholds['MEMORY']:.1f}% | STORAGE={engine.active_thresholds['STORAGE']:.1f}% | NETWORK={engine.active_thresholds['NETWORK']:.1f}%")
        
        # THINK: Evaluate state and get culprit
        culprit = engine.evaluate_state(state)
        
        # ACT: If a culprit exists, execute the policy
        if culprit is not None:
            current_value = float(state.get(culprit, 0.0))
            level, action_message = healer.execute_policy(culprit, current_value)
            print(f"ACTION: {action_message}")
        else:
            print("STATUS: System Healthy")
        
        print()
        
        # Sleep for readability
        time.sleep(1.5)
    
    print("=" * 80)
    print("VALIDATION COMPLETE")
    print("=" * 80)
    print()
    print("Final System State:")
    for metric in ["CPU", "MEMORY", "STORAGE", "NETWORK"]:
        metric_state = healer.state[metric]
        print(f"  {metric}: Level={metric_state['current_level']}, Retry={metric_state['retry_count']}, Halted={metric_state['is_halted']}")


if __name__ == "__main__":
    main()
