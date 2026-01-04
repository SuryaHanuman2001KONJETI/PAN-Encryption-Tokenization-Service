

```markdown
# 🔐 PAN Encryption & Tokenization Service

This project is a backend service designed to securely handle credit card Primary Account Numbers (PANs). The main idea of this system is to make sure that sensitive card information is never stored or exposed in plain text. Instead, the PAN is encrypted immediately and replaced with a secure token that can be safely used by other systems.

The project is built for learning purposes and follows security practices commonly used in real-world payment systems.

---

## 📖 About the Project

Storing or handling card details without protection can lead to serious security risks. In this project, whenever a PAN is received, it is encrypted using strong cryptography and a unique token is generated. The original PAN is never saved in readable form.

Only authorized administrators are allowed to decrypt the PAN, while regular users can only see masked card details. This approach reduces the risk of data leakage and demonstrates how sensitive data should be managed in backend systems.

---

## ✨ Key Features

- Encrypts PANs using AES-GCM encryption  
- Replaces PANs with randomly generated tokens  
- Shows masked PANs (first 6 and last 4 digits only)  
- Allows PAN decryption only for authorized admins  
- Stores only encrypted data in the database  
- Provides interactive API testing using Swagger  

---

## 🏗️ How the System Works

```

Client sends PAN
↓
PAN is validated
↓
PAN is encrypted securely
↓
Token is generated
↓
Encrypted data is stored
↓
Token and masked PAN are returned

````

This flow ensures that sensitive card data is always protected.

---

## 🛠️ Technologies Used

- Python  
- FastAPI  
- Cryptography library (AES-GCM)  
- SQLite database  
- Pydantic for request validation  
- Uvicorn server  

---

## 🚀 Running the Project

### Step 1: Clone the Repository
```bash
git clone https://github.com/your-username/pan-encryption-tokenization.git
cd pan-encryption-tokenization
````

### Step 2: Create a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Set Environment Variables

Create a `.env` file in the project folder:

```env
MASTER_KEY_HEX=your_32_byte_hex_key_here
ADMIN_API_KEY=your_admin_key_here
DATABASE=./tokens.db
```

### Step 5: Start the Server

```bash
uvicorn main:app --reload
```

---

## 🌐 API Documentation

Once the server is running, open the browser and visit:

```
http://127.0.0.1:8000/docs
```

This page allows you to test all APIs easily.

---

## 🔌 Available API Endpoints

| Endpoint         | Method | Purpose                        |
| ---------------- | ------ | ------------------------------ |
| `/`              | GET    | Shows service information      |
| `/encrypt`       | POST   | Encrypts PAN and returns token |
| `/decrypt`       | POST   | Decrypts PAN (admin only)      |
| `/token/{token}` | GET    | Returns token details          |
| `/health`        | GET    | Checks service status          |

---

## 🔐 Security Considerations

* Raw PANs are never stored or logged
* Encryption keys are kept outside the source code
* Each encryption uses a unique nonce
* Decryption requires an admin API key
* Only masked PANs are shown to users

---

## ⚠️ Important Note

This project is created for **educational purposes**. While it follows strong security principles, it is not officially PCI-DSS compliant and should not be used directly in production without additional protections.

---

## 🔮 Future Improvements

* Key rotation support
* Role-based authentication
* Rate limiting on sensitive endpoints
* Audit logs for admin actions
* Integration with secure key vaults
* Format-Preserving Encryption (FPE)

---

## 📌 Conclusion

This project helped me understand how sensitive data should be handled in backend systems. By using encryption, tokenization, and access control, the system ensures that card information remains secure at every stage. It serves as a strong foundation for learning secure backend and fintech development concepts.

---

## 👤 Author

**Surya Hanuman KONJETI**
Backend / Cybersecurity Enthusiast

