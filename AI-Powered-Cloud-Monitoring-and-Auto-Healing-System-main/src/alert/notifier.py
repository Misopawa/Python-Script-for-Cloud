def send_alert(message, logger):
    """
    Send an alert by logging the provided message.

    Args:
        message (str): The alert message to be logged.
        logger: A logger instance used to log the alert.

    Note:
        This function currently only logs alerts. Future work can extend this
        to integrate with external messaging services (e.g., email, Slack, SMS).
    """
    logger.warning("ALERT: %s", message)
