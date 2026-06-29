import random
from datetime import datetime, timedelta


def generate_otp():
    """
    Generate a random 6-digit OTP.
    """

    otp = random.randint(100000, 999999)

    return str(otp)
def save_otp(cursor,user_id, otp):

    


    expires_at = datetime.now() + timedelta(minutes=2)
    cursor.execute(
    """
    INSERT INTO otp_codes
    (user_id, otp, expires_at)

    VALUES (?, ?, ?)
    """,
    (
        user_id,
        otp,
        expires_at,
    ),
 )
    
