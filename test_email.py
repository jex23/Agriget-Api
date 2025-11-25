import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Email configuration
mail_host = os.getenv("MAIL_HOST")
mail_port = int(os.getenv("MAIL_PORT", 465))
mail_username = os.getenv("MAIL_USERNAME")
mail_password = os.getenv("MAIL_PASSWORD")
mail_from_address = os.getenv("MAIL_FROM_ADDRESS")
mail_from_name = os.getenv("MAIL_FROM_NAME")

def send_test_email():
    """
    Send a test order email
    """
    try:
        # Test email parameters
        recipient_email = "jamesgalos223@gmail.com"
        recipient_name = "James Galos"
        order_number = "TEST-001"
        order_status = "confirmed"
        product_name = "Test Product"
        quantity = 10.0
        total_amount = 1500.00
        payment_status = "pending"

        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{mail_from_name} <{mail_from_address}>"
        msg['To'] = recipient_email
        msg['Subject'] = f"Order {order_status.replace('_', ' ').title()} - #{order_number}"

        # Create HTML email body
        html = f"""
        <html>
          <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
              <h2 style="color: #2c5f2d; border-bottom: 2px solid #2c5f2d; padding-bottom: 10px;">
                Order {order_status.replace('_', ' ').title()}
              </h2>

              <p>Dear {recipient_name},</p>

              <p>This is a <strong>TEST EMAIL</strong> from the Agrivet API order system.</p>

              <p>Your order status has been updated. Here are the details:</p>

              <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr style="background-color: #f4f4f4;">
                  <td style="padding: 10px; border: 1px solid #ddd;"><strong>Order Number:</strong></td>
                  <td style="padding: 10px; border: 1px solid #ddd;">#{order_number}</td>
                </tr>
                <tr>
                  <td style="padding: 10px; border: 1px solid #ddd;"><strong>Product:</strong></td>
                  <td style="padding: 10px; border: 1px solid #ddd;">{product_name}</td>
                </tr>
                <tr style="background-color: #f4f4f4;">
                  <td style="padding: 10px; border: 1px solid #ddd;"><strong>Quantity:</strong></td>
                  <td style="padding: 10px; border: 1px solid #ddd;">{quantity}</td>
                </tr>
                <tr>
                  <td style="padding: 10px; border: 1px solid #ddd;"><strong>Total Amount:</strong></td>
                  <td style="padding: 10px; border: 1px solid #ddd;">PHP {total_amount:,.2f}</td>
                </tr>
                <tr style="background-color: #f4f4f4;">
                  <td style="padding: 10px; border: 1px solid #ddd;"><strong>Payment Status:</strong></td>
                  <td style="padding: 10px; border: 1px solid #ddd;">{payment_status.replace('_', ' ').title()}</td>
                </tr>
                <tr>
                  <td style="padding: 10px; border: 1px solid #ddd;"><strong>Order Status:</strong></td>
                  <td style="padding: 10px; border: 1px solid #ddd;">{order_status.replace('_', ' ').title()}</td>
                </tr>
              </table>

              <p>Thank you for your order!</p>

              <p style="color: #666; font-size: 12px; margin-top: 30px; border-top: 1px solid #ddd; padding-top: 10px;">
                This is an automated email from {mail_from_name}. Please do not reply to this email.
              </p>
            </div>
          </body>
        </html>
        """

        # Attach HTML content
        msg.attach(MIMEText(html, 'html'))

        # Check if email configuration is set
        print("=== EMAIL CONFIGURATION ===")
        print(f"MAIL_HOST: {mail_host if mail_host else '✗ Missing'}")
        print(f"MAIL_PORT: {mail_port}")
        print(f"MAIL_USERNAME: {'✓ Set' if mail_username else '✗ Missing'}")
        print(f"MAIL_PASSWORD: {'✓ Set' if mail_password else '✗ Missing'}")
        print(f"MAIL_FROM_ADDRESS: {mail_from_address if mail_from_address else '✗ Missing'}")
        print(f"MAIL_FROM_NAME: {mail_from_name if mail_from_name else '✗ Missing'}")
        print("===========================\n")

        if not all([mail_host, mail_username, mail_password, mail_from_address]):
            print("❌ ERROR: Missing required email configuration. Please check your .env file.")
            return False

        # Connect to SMTP server and send email
        print(f"Connecting to SMTP server {mail_host}:{mail_port}...")
        with smtplib.SMTP_SSL(mail_host, mail_port) as server:
            print("Logging in...")
            server.login(mail_username, mail_password)
            print("Sending email...")
            server.send_message(msg)

        print(f"✅ Email sent successfully to {recipient_email}")
        return True

    except Exception as e:
        print(f"❌ Failed to send email: {str(e)}")
        return False

if __name__ == "__main__":
    print("Testing SMTP email functionality...\n")
    send_test_email()
