# encoding.py
import qrcode
import base64
from io import BytesIO

class QREncoder:
    """QR Code generation"""
    
    @staticmethod
    def generate_qr(data, size=10):
        """Generate QR code for data"""
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=size,
                border=4,
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
            
            return f"data:image/png;base64,{img_str}"
        except Exception as e:
            print(f"QR generation failed: {e}")
            return None
    
    @staticmethod
    def generate_message_qr(message_id, base_url):
        """Generate QR code for message extraction URL"""
        extraction_url = f"{base_url}extract/{message_id}"
        return QREncoder.generate_qr(extraction_url)