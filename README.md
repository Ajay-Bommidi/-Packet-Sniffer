# 🚀 Advanced Network Packet Sniffer

An advanced, user-friendly **Network Packet Sniffer** built with **Python**. This tool captures, analyzes, and logs network packets, displaying key details such as **source/destination IPs, protocols, and packet size**. Each capture session is saved as a **.pcap file**, which can be analyzed using tools like **Wireshark**. 
![Screenshot 2025-03-12 122621](https://github.com/user-attachments/assets/5ba13765-bd52-4325-9fdd-85b915a4acbe)


---

## ✨ Features
✅ **User-selectable network interface** for targeted sniffing  
✅ **Real-time packet capture** with a detailed CLI display  
✅ **Live packet statistics** with a progress bar  
✅ **Protocol detection** (TCP, UDP, ICMP, etc.)  
✅ **Colorful CLI output** using `rich` and `colorama`  
✅ **Saves each session as a separate `.pcap` file** for future analysis  
✅ **Optimized for performance & user-friendliness**  

---

## 📂 Installation
### **1️⃣ Install Dependencies**
```sh
pip install scapy colorama tabulate rich psutil pyfiglet
```

### **2️⃣ Clone the Repository**
```sh
https://github.com/Ajay-Bommidi/PRODIGY_CS_05.git
```

### **3️⃣ Run the Sniffer**
```sh
python network-sniffer.py
```

---

## 📜 How It Works
1️⃣ **Choose a network interface** from the available list  
2️⃣ **Packets are captured and displayed live** in a structured table  
3️⃣ **Each capture session is saved** as a `.pcap` file for later analysis  
4️⃣ **Press `CTRL+C` to stop capturing** and view summary statistics  

---

## 📊 Example Output
```
=====================================
        PACKET SNIFFER TOOL         
=====================================
🔍 Available Network Interfaces:
[1] Wi-Fi
[2] Ethernet
👉 Select an interface: 1

🚀 Starting Packet Capture on Wi-Fi...

⏳ Time       | 🏠 Source IP       | 🎯 Destination IP    | 🔗 Protocol | 📦 Size (bytes)
-------------|-------------------|---------------------|------------|--------------
12:30:45     | 192.168.1.10       | 142.250.183.206    | TCP        | 1500
12:30:47     | 192.168.1.10       | 8.8.8.8            | ICMP       | 98

📂 Saving packets to: captures/capture_2025-03-05_12-30-45.pcap
``` 

---

## 🛠 Future Enhancements
🔹 GUI version for better user experience  
🔹 Filter packets by specific protocols  
🔹 Export packet logs in structured formats (CSV, JSON)  

---

## ⚠️ Ethical Considerations
> **This tool is for educational & network analysis purposes only.** Do **not** use it for unauthorized monitoring, as it may violate privacy laws. Always obtain proper permissions before capturing network traffic.

---


## 📜 License
Licensed under the **MIT License**. See `LICENSE` for details.

---

### 🎯 Developed by **[Ajay BOmmidi]** 👨‍💻
