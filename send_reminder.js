/**
 * MemoriaGraph / AI-SRE Scheduled Reminder Script
 * Mengirimkan pesan pengingat agenda ke WhatsApp pribadi Maskii
 */
const { sendWhatsAppAlert, loadConfig } = require('./src/alert');
const fs = require('fs');
const path = require('path');

const FLAG_FILE = path.resolve(__dirname, 'logs/reminder_strix_sent.flag');

async function main() {
  if (fs.existsSync(FLAG_FILE)) {
    console.log('Reminder already sent previously. Exiting.');
    return;
  }

  const config = loadConfig();
  const phone = config.alertPhone || process.env.ALERT_WA_NUMBER;
  if (!phone) {
    console.error('No ALERT_WA_NUMBER configured in .env. Exiting.');
    return;
  }

  const reminderMsg =
    `🌅 *PENGINGAT AGENDA DARI FRIDAY* 🌅\n\n` +
    `Selamat pagi, Bos Maskii! ☕\n\n` +
    `Sesuai rencana kita, berikut adalah agenda riset & eksperimen hari ini di kantor:\n\n` +
    `📌 *Agenda Eksperimen Hari Ini:*\n` +
    `1. *Uji Coba Strix AI Security*:\n` +
    `   • Konfigurasi backend LLM menggunakan *Google AI Studio (Gemini Flash)*.\n` +
    `   • Menyiapkan sandbox Docker di server vm-maskii.\n` +
    `   • Pengujian terisolasi & integrasi pelaporan ke n8n.\n\n` +
    `2. *Explore AI YouTube Clipper (100% Free / Zero-Cost)*:\n` +
    `   • Merancang pipeline kliping video otomatis gratis.\n` +
    `   • Opsi arsitektur: n8n workflow (yt-dlp + Gemini Flash + ffmpeg) atau Slendro AI.\n` +
    `   • Deteksi auto-highlight & auto-crop format Shorts/Reels/TikTok.\n\n` +
    `⏰ Waktu: Senin, 28 September 2026 - 08:00 WIB\n` +
    `🤖 Server Status: vm-maskii 32GB standby & siap gaspol!\n\n` +
    `Ketik pesan kapan pun Bos luang dan siap mulai! 🚀`;

  console.log(`Sending WhatsApp reminder to ${phone}...`);
  try {
    const res = await sendWhatsAppAlert(phone, reminderMsg);
    console.log('WhatsApp reminder sent successfully:', res);
    fs.writeFileSync(FLAG_FILE, new Date().toISOString());
  } catch (err) {
    console.error('Failed to send reminder:', err.message);
    process.exit(1);
  }
}

main();
