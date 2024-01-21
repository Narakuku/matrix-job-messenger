#!/usr/bin/env python3
import os
import asyncio
import json
import logging
from dotenv import load_dotenv
from nio import (
    AsyncClient,
    ClientConfig,
    crypto,
    LoginResponse,
    SyncResponse,
    LoginResponse,
    DevicesResponse,
    SyncError,
    JoinError,
    LocalProtocolError,
    ToDeviceError,
    KeyVerificationCancel,
    KeyVerificationEvent,
    KeyVerificationKey,
    KeyVerificationMac,
    KeyVerificationStart,
    )
from task_check_urls import check_urls  # Import the function that generates the messages

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Client configuration for end-to-end encryption
config = ClientConfig(store_sync_tokens=True, encryption_enabled=True)

async def handle_key_verification(client, event):
    """
    Handle key verification events.

    :param client: The Matrix AsyncClient instance.
    :param event: The key verification event.
    """
    logger.info(f"Received key verification event: {event}")

    if isinstance(event, KeyVerificationStart):
        logger.info(f"KeyVerificationStart event: {event}")
        if "emoji" not in event.short_authentication_string:
            await client.cancel_key_verification(event.transaction_id)
            logger.info("Only support Emoji verification, key verification cancelled.")
        else:
            await client.accept_key_verification(event.transaction_id)
            logger.info("Emoji verification accepted.")
            await asyncio.sleep(5)  # Add a short delay to prevent overflow
    elif isinstance(event, KeyVerificationCancel):
        logger.info(f"KeyVerificationCancel event: {event}")
        logger.info("Key verification cancelled.")
    elif isinstance(event, KeyVerificationKey):
        logger.info(f"KeyVerificationKey event: {event}")
        await client.confirm_short_auth_string(event.transaction_id)
        logger.info("Short authentication string confirmed.")
        await asyncio.sleep(5)  # Add a short delay to prevent overflow
    elif isinstance(event, KeyVerificationMac):
        logger.info(f"KeyVerificationMac event: {event}")
        logger.info("Emoji verification was successful!")
    else:
        logger.info(f"Unhandled key verification event type: {type(event)}")

async def collect_and_send_messages(client, room_id, tasks_to_run):
    """
    Collect messages from tasks and send them to the specified Matrix room.
    
    :param client: The Matrix AsyncClient instance.
    :param room_id: The ID of the Matrix room to send messages to.
    :param tasks_to_run: A list of tasks to run and collect messages from.
    """
    task_coroutines = [run_task(task_func, task_name, *task_args) for task_name, task_func, task_args in tasks_to_run]
    all_messages = await asyncio.gather(*task_coroutines)
    all_messages = [message for sublist in all_messages for message in sublist]

    for message in all_messages:
        if message:
            await client.room_send(
                room_id=room_id,
                message_type="m.room.message",
                content={
                    "msgtype": "m.text",
                    "body": message
                }
            )
            logger.info(f"Message sent: {message}")

async def run_task(task_func, task_name, *args, **kwargs):
    """
    Execute a given task function asynchronously and handle any exceptions.
    
    :param task_func: The coroutine function representing the task.
    :param task_name: The name of the task for logging purposes.
    :param args: Positional arguments to pass to the task function.
    :param kwargs: Keyword arguments to pass to the task function.
    :return: The result of the task function or an error message.
    """
    try:
        return await task_func(*args, **kwargs)
    except Exception as e:
        error_message = f"An error occurred while executing {task_name}: {e}"
        logger.error(error_message)
        return [error_message]

async def trust_unverified_devices(client):
    """
    Trust unverified devices from the device store, including the user's own devices.
    
    :param client: The Matrix AsyncClient instance.
    """
    try:
        # Perform a sync to update the device store
        await client.sync(timeout=30000, full_state=True)

        # Fetch the list of the user's own devices
        devices_response = await client.devices()
        if not isinstance(devices_response, DevicesResponse):
            logger.error(f"Failed to fetch own devices: {devices_response}")
            return

        # Create a set of own device IDs for quick lookup
        own_device_ids = {device.id for device in devices_response.devices}

        # Trust unverified devices from the device store, including the user's own devices
        device_store: crypto.DeviceStore = client.device_store
        for user_id, devices in device_store.items():
            for device_id, device_info in devices.items():
                # Skip the current device and already verified devices
                if device_id == client.device_id or device_info.verified:
                    continue

                # Trust the device if it's one of the user's own devices
                if user_id == client.user_id and device_id in own_device_ids:
                    client.verify_device(device_info)
                    logger.info(f"Trusted own unverified device: {device_id} of user {user_id}")
                # Optionally trust other users' unverified devices (be cautious with this)
                elif user_id != client.user_id:
                    client.verify_device(device_info)
                    logger.info(f"Trusted other unverified device: {device_id} of user {user_id}")
    except Exception as e:
        logger.error(f"An error occurred while trusting devices: {e}")

async def fetch_missing_device_keys(client):
    """
    Fetch missing device keys from the server.
    
    :param client: The Matrix AsyncClient instance.
    """
    try:
        # Perform a sync to get the latest room state
        await client.sync(timeout=30000, full_state=True)

        # Attempt to fetch missing device keys
        await client.keys_query()
    except LocalProtocolError as e:
        logger.debug(f"No key query required: {e}")
    except Exception as e:
        logger.error(f"An error occurred while fetching missing device keys: {e}")

async def upload_own_device_keys(client):
    """
    Sync encryption keys with the server if needed.
    
    :param client: The Matrix AsyncClient instance.
    """
    try:
        if client.should_upload_keys:
            await client.keys_upload()
    except Exception as e:
        logger.error(f"An error occurred while uploading device keys: {e}")

async def auto_join_invites(client):
    """
    Automatically join rooms when invited.
    
    :param client: The Matrix AsyncClient instance.
    """
    try:
        await client.sync(timeout=30000, full_state=True)
        invites = client.invited_rooms
        if invites:
            for room_id in invites:
                # Join the room
                join_response = await client.join(room_id)
                if isinstance(join_response, JoinError):
                    logger.error(f"Failed to join room: {room_id}, error: {join_response}")
                else:
                    logger.info(f"Joined room: {room_id}")
    except Exception as e:
        logger.error(f"An error occurred while auto-joining invites: {e}")

async def login_with_password(client, my_password, my_device_name, my_session_file):
    """
    Log in to the Matrix server using a password.
    
    :param client: The Matrix AsyncClient instance.
    :param my_password: The user's password.
    :param my_device_name: The name of the device.
    :param my_session_file: The path to the session file.
    :return: True if login was successful, False otherwise.
    """
    try:
        response = await client.login(my_password, device_name=my_device_name)
        if isinstance(response, LoginResponse):
            logger.info(f"Logged in with new session: device_id={response.device_id}, access_token={response.access_token}")
            save_session_to_file(my_session_file, response.device_id, response.access_token)
            return True
        else:
            logger.error(f"Failed to log in: {response}")
            return False
    except Exception as e:
        logger.error(f"An error occurred while logging in with password: {e}")
        return False

async def login_with_token(client, my_user_id, my_device_id, my_access_token, my_password, my_device_name, my_session_file):
    """
    Log in to the Matrix server using an access token, or fall back to password login.
    
    :param client: The Matrix AsyncClient instance.
    :param my_user_id: The user's Matrix ID.
    :param my_device_id: The device ID.
    :param my_access_token: The access token.
    :param my_password: The user's password.
    :param my_device_name: The name of the device.
    :param my_session_file: The path to the session file.
    :return: True if login was successful, False otherwise.
    """
    try:
        if my_access_token and my_device_id:
            client.restore_login(user_id=my_user_id, device_id=my_device_id, access_token=my_access_token)
            # Perform a sync to validate the session
            sync_response = await client.sync(timeout=30000)
            if isinstance(sync_response, SyncResponse):
                logger.info(f"Restored session for {my_user_id}")
                return True
            else:
                logger.warning(f"Failed to restore session: {sync_response.message if isinstance(sync_response, SyncError) else 'Unknown error'}, proceeding with password login.")
                return await login_with_password(client, my_password, my_device_name, my_session_file)
        else:
            logger.info("Missing device_id or access_token for session restoration, proceeding with password login.")
            return await login_with_password(client, my_password, my_device_name, my_session_file)
    except Exception as e:
        logger.error(f"An error occurred while logging in with token: {e}")
        return False

async def initialize_client(homeserver, user_id, device_id, store_path, config):
    """
    Initialize the Matrix AsyncClient.
    
    :param homeserver: The URL of the Matrix homeserver.
    :param user_id: The user's Matrix ID.
    :param device_id: The device ID.
    :param store_path: The path to the store directory.
    :param config: The ClientConfig instance.
    :return: An instance of AsyncClient.
    """
    client = AsyncClient(homeserver, user_id, device_id=device_id, store_path=store_path, config=config)
    return client

def save_session_to_file(session_file, device_id, access_token):
    """
    Save the session details to a separate JSON file.
    """
    try:
        with open(session_file, 'w') as file:
            json.dump({'device_id': device_id, 'access_token': access_token}, file)
        logger.info(f"Session saved to {session_file}")
    except Exception as e:
        logger.error(f"An error occurred while saving the session to file: {e}")

def load_session_from_file(session_file):
    """
    Load the session details from a JSON file.
    """
    try:
        if os.path.exists(session_file):
            with open(session_file, 'r') as file:
                session = json.load(file)
                return session.get('device_id'), session.get('access_token')
        else:
            return None, None
    except Exception as e:
        logger.error(f"An error occurred while loading the session from file: {e}")
        return None, None

async def main():
    """
    The main function to run the Matrix client and perform tasks.
    """
    client = None
    try:
        # Load environment variables from .env file
        load_dotenv()

        # Environment variables
        my_homeserver = os.getenv('MATRIX_HOMESERVER_URL')
        my_user_id = os.getenv('MATRIX_USER_ID')
        my_password = os.getenv('MATRIX_PASSWORD')
        my_room_id = os.getenv('MATRIX_ROOM_ID')
        my_store_path = os.getenv('MATRIX_STORE_PATH')
        my_device_id = os.getenv('MATRIX_DEVICE_ID')
        my_device_name = os.getenv('MATRIX_DEVICE_NAME')
        my_access_token = os.getenv('MATRIX_ACCESS_TOKEN')

        # Validate required environment variables
        required_vars = [my_homeserver, my_user_id, my_password, my_room_id, my_store_path]
        if not all(required_vars):
            logger.error("One or more required environment variables are missing.")
            return

        # Ensure the store path exists
        os.makedirs(my_store_path, exist_ok=True)
        my_session_file = os.path.join(my_store_path, 'session.json')

        # Load session details from the session file if the .env variables are empty
        if not my_device_id or not my_access_token:
            my_device_id, my_access_token = load_session_from_file(my_session_file)

        client = await initialize_client(my_homeserver, my_user_id, my_device_id, my_store_path, config)

        login_successful = await login_with_token(client, my_user_id, my_device_id, my_access_token, my_password, my_device_name, my_session_file)
        if not login_successful:
            return

        await auto_join_invites(client)
        await upload_own_device_keys(client)
        await fetch_missing_device_keys(client)
        await trust_unverified_devices(client)

        # Define a dictionary to map task names to coroutine functions and arguments
        tasks_to_run = [
            ("check_urls", check_urls, []),
            # ("another_task", another_task, [arg1, arg2]),  # Example with arguments
        ]

        # Send all collected messages to Matrix
        await collect_and_send_messages(client, my_room_id, tasks_to_run)

        # Define a callback for to-device events
        def to_device_callback(event):
            asyncio.create_task(handle_key_verification(client, event))

        # Register the callback with the client
        client.add_to_device_callback(to_device_callback, (KeyVerificationEvent,))

        # Start the client's sync_forever loop
        await client.sync_forever(timeout=30000, full_state=True)

    except KeyboardInterrupt:
        logger.info("Program interrupted by user, shutting down.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
    finally:
        if client:
            await client.close()
            logger.info("Matrix client closed.")

if __name__ == "__main__":
    asyncio.run(main())

