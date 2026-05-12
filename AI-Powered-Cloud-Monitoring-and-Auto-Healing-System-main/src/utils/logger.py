import logging
import os

def get_logger(name):
    """
    Configures and returns a logger instance.
    
    Args:
        name (str): The name of the logger (typically __name__).
        
    Returns:
        logging.Logger: A configured logger instance.
    """
    # Define the log directory and file
    log_dir = 'logs'
    log_file = 'system.log'
    log_path = os.path.join(log_dir, log_file)

    # Ensure the logs directory exists
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Create a custom logger
    logger = logging.getLogger(name)
    
    # Set the logging level (INFO captures everything from INFO up to CRITICAL)
    logger.setLevel(logging.INFO)

    # Avoid adding multiple handlers if get_logger is called multiple times for the same name
    if not logger.handlers:
        # Create handlers
        f_handler = logging.FileHandler(log_path)

        # Set level for handlers
        f_handler.setLevel(logging.INFO)

        # Create formatters and add it to handlers
        # Format: Timestamp - Logger Name - Log Level - Message
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        f_handler.setFormatter(formatter)

        # Add handlers to the logger
        logger.addHandler(f_handler)

    return logger
 
def setup_logger():
    return get_logger("cloud_monitor")
