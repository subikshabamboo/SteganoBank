# steganography.py
from stegano import lsb
from PIL import Image
import numpy as np
from scipy import stats

class Steganography:
    """LSB Steganography for hiding messages"""
    
    @staticmethod
    def hide_message(cover_image_path, message, output_path):
        """Hide message in image using LSB"""
        try:
            secret_image = lsb.hide(cover_image_path, message)
            secret_image.save(output_path, 'PNG')
            return True
        except Exception as e:
            print(f"Steganography hiding failed: {e}")
            return False
    
    @staticmethod
    def extract_message(stego_image_path):
        """Extract hidden message from stego image"""
        try:
            message = lsb.reveal(stego_image_path)
            return message if message else None
        except Exception as e:
            print(f"Steganography extraction failed: {e}")
            return None
    
    @staticmethod
    def get_image_capacity(image_path):
        """Calculate maximum message capacity"""
        try:
            img = Image.open(image_path)
            width, height = img.size
            capacity = (width * height * 3) // 8
            return capacity
        except Exception as e:
            print(f"Capacity calculation failed: {e}")
            return 0

    @staticmethod
    def chi_square_attack(image_path):
        """
        Chi-square test to detect LSB steganography
        Returns detection result and confidence
        """
        try:
            img = Image.open(image_path).convert('RGB')
            pixels = np.array(img)
            
            # Flatten and get LSBs
            flat_pixels = pixels.flatten()
            lsbs = flat_pixels & 1  # Extract least significant bits
            
            # Count pairs
            total_pixels = len(lsbs)
            zeros = np.sum(lsbs == 0)
            ones = np.sum(lsbs == 1)
            
            # Expected distribution: 50/50
            expected = total_pixels / 2
            
            # Chi-square statistic
            chi2_stat = ((zeros - expected)**2 / expected + 
                        (ones - expected)**2 / expected)
            
            # Critical value at 95% confidence (df=1)
            critical_value = 3.841
            
            # p-value
            p_value = 1 - stats.chi2.cdf(chi2_stat, df=1)
            
            # Detection logic
            is_suspicious = chi2_stat > critical_value
            confidence = (1 - p_value) * 100 if is_suspicious else p_value * 100
            
            return {
                'detected': is_suspicious,
                'chi2_statistic': round(chi2_stat, 4),
                'p_value': round(p_value, 4),
                'confidence': round(confidence, 2),
                'critical_value': critical_value,
                'verdict': 'SUSPICIOUS - May contain hidden data' if is_suspicious else 'CLEAN - No hidden data detected'
            }
        except Exception as e:
            return {
                'error': str(e),
                'detected': None
            }
    
    @staticmethod
    def histogram_analysis(image_path):
        """Analyze pixel value distribution"""
        try:
            img = Image.open(image_path).convert('RGB')
            pixels = np.array(img)
            
            # Calculate histogram
            hist, bins = np.histogram(pixels.flatten(), bins=256, range=(0, 256))
            
            # Check for anomalies
            std_dev = np.std(hist)
            mean = np.mean(hist)
            
            return {
                'mean_frequency': round(mean, 2),
                'std_deviation': round(std_dev, 2),
                'uniformity_score': round((std_dev / mean) * 100, 2) if mean > 0 else 0
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def visual_quality_metrics(image_path):
        """Calculate image quality metrics"""
        try:
            img = Image.open(image_path).convert('RGB')
            pixels = np.array(img, dtype=np.float64)
            
            # Calculate metrics
            total_pixels = pixels.size
            pixel_range = np.ptp(pixels)  # Peak to peak (max - min)
            
            return {
                'resolution': f"{img.size[0]}x{img.size[1]}",
                'total_pixels': total_pixels,
                'color_depth': '24-bit RGB',
                'value_range': f"0-{int(pixel_range)}",
                'capacity_bytes': int((total_pixels * 3) / 8)  # LSB capacity
            }
        except Exception as e:
            return {'error': str(e)}