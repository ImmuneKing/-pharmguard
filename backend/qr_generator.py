import qrcode
from app import encrypt_data
import json

def generate_qr_code(serial_number, manufacturer, expiration_date):
    """
    Generate QR code with encrypted drug information
    """
    # Create data dictionary
    data = {
        'serial_number': serial_number,
        'manufacturer': manufacturer,
        'expiration_date': expiration_date
    }
    
    # Convert to string and encrypt
    data_str = json.dumps(data)
    encrypted_data = encrypt_data(data_str)
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    
    qr.add_data(encrypted_data)
    qr.make(fit=True)
    
    # Create image
    img = qr.make_image(fill_color="black", back_color="white")
    return img

if __name__ == '__main__':
    # Example usage
    img = generate_qr_code(
        serial_number="DRUG123456",
        manufacturer="Pharma Corp",
        expiration_date="2024-12-31"
    )
    img.save("drug_qr.png") 