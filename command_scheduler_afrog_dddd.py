#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import subprocess
import time
import datetime
import logging
import json
import atexit
import signal
import logging.handlers
import shlex
import fcntl

# --- Sabitler ---
CONFIG_FILE = "scheduler_config.json"
LOCK_FILE = "scheduler.lock"

# --- Varsayılan Komut Listesi ---
DEFAULT_COMMANDS = [
    "dddd -ni -t httpx.txt -output-type text -o dddd-scan-script-script-result.txt -html-output dddd-scan-script-result.html | tee -a teedddd-result-script.txt",
    "afrog -silent -duc -T httpx.txt -S medium,high,critical -o afrog_all-script-result.html -c 200  | tee -a teeafrog-result-script.txt",
    "nuclei -duc -ni -l httpx.txt -es info,low -o nuclei-script-result.txt -c 100 -etags wordpress,wp-plugin | tee -a teenuclei-result-script.txt"
]
# --- Loglama Kurulumu (Global Fonksiyon)---
def setup_logging(log_file):
    """Rote edilen, hem dosyaya hem konsola yazan loglama sistemi kurar."""
    logger = logging.getLogger() # Kök logger'ı al
    logger.setLevel(logging.INFO)
    # Mevcut handler'ları temizle (tekrar tekrar çağrılma durumuna karşı)
    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s - [%(levelname)s] - %(message)s")
    
    # Dosya Handler (Rote edilen)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=1048576, backupCount=5, encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Konsol Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

# --- Kilit Dosyası Yönetimi (Global Fonksiyonlar)---
def acquire_lock():
    """Lock dosyası oluşturur ve kilitler. Zaten kilitliyse None döner."""
    try:
        lock_fd = open(LOCK_FILE, 'w')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_fd.write(str(os.getpid()))
        lock_fd.flush()
        return lock_fd
    except IOError:
        logging.error(f"Lock dosyası ({LOCK_FILE}) alınamadı. Başka bir betik kopyası zaten çalışıyor olabilir.")
        return None

def release_lock(lock_fd):
    """Lock dosyasını serbest bırakır ve siler."""
    if lock_fd:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()
        # Dosyanın varlığını kontrol et, başka bir süreç silmiş olabilir
        if os.path.exists(LOCK_FILE):
            os.remove(LOCK_FILE)
        logging.info("Kilit serbest bırakıldı.")

def format_timedelta(td):
    """Zaman farkını okunabilir bir metne çevirir."""
    total_seconds = int(td.total_seconds())
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    parts = []
    if days > 0:
        parts.append(f"{days} gün")
    if hours > 0:
        parts.append(f"{hours} saat")
    if minutes > 0:
        parts.append(f"{minutes} dakika")
    if seconds > 0 or not parts:
        parts.append(f"{seconds} saniye")
        
    return ", ".join(parts)

class CommandScheduler:
    def __init__(self, command_file_path):
        self.config = self._load_config()
        setup_logging(self.config["LOG_FILE"]) # Loglamayı config ile başlat
        
        self.command_file_path = command_file_path
        self.commands = self._load_commands()
        self.next_command_index = self._load_state()
        self.current_process = None
        
        atexit.register(self.cleanup_on_exit)

    def _load_config(self):
        """Yapılandırmayı JSON dosyasından yükler ve varsayılanlarla birleştirir."""
        default_config = {
            "STATE_FILE": "scheduler_state.json",
            "LOG_FILE": "scheduler.log",
            "COMMAND_OUTPUT_LOG_FILE": "command_outputs.log",
            "ALL_WEEK_SCAN": True,
            "WEEKEND_SCAN": False,
            "KILL_ONLY_STARTED_PROCESS": True,
            "ALL_WEEK_START": "00:00",
            "ALL_WEEK_END": "07:00",
            "WEEKEND_START": "00:10",
            "WEEKEND_END": "07:00",
            "LOOP_SLEEP_INTERVAL": 15
        }
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except (json.JSONDecodeError, IOError) as e:
                # Loglama henüz hazır değil, print kullan
                print(f"UYARI: Config dosyası ({CONFIG_FILE}) okunamadı: {e}. Varsayılanlar kullanılıyor.")
        
        # Zaman string'lerini datetime.time nesnelerine çevir
        for key in ["ALL_WEEK_START", "ALL_WEEK_END", "WEEKEND_START", "WEEKEND_END"]:
            default_config[key] = datetime.time.fromisoformat(default_config[key])
        return default_config

    def _load_commands(self):
        """Komut dosyasını okur, yoksa varsayılan komutları kullanır."""
        if self.command_file_path:
            try:
                with open(self.command_file_path, 'r', encoding='utf-8') as f:
                    commands = [line.strip() for line in f if line.strip()]
                    logging.info(f"Komut dosyası yüklendi: {self.command_file_path} ({len(commands)} komut)")
                    return commands
            except FileNotFoundError:
                logging.error(f"Komut dosyası bulunamadı: {self.command_file_path}")
                sys.exit(1)
        else:
            logging.info(f"Varsayılan komutlar kullanılıyor ({len(DEFAULT_COMMANDS)} komut)")
            return DEFAULT_COMMANDS.copy()

    def _load_state(self):
        """Durum dosyasından indeksi yükler."""
        state_file = self.config["STATE_FILE"]
        if not os.path.exists(state_file):
            return 0
        try:
            with open(state_file, 'r') as f:
                return json.load(f).get("next_command_index", 0)
        except (json.JSONDecodeError, IOError) as e:
            logging.error(f"Durum dosyası ({state_file}) okunamadı: {e}. Baştan başlanıyor.")
            return 0

    def _save_state(self):
        """Mevcut indeksi durum dosyasına kaydeder."""
        try:
            with open(self.config["STATE_FILE"], 'w') as f:
                json.dump({"next_command_index": self.next_command_index}, f)
        except IOError as e:
            logging.error(f"Durum dosyasına ({self.config['STATE_FILE']}) yazılamadı: {e}")

    def _is_running_window(self):
        """Mevcut zamanın çalışma aralığında olup olmadığını kontrol eder."""
        now = datetime.datetime.now()
        weekday = now.weekday()
        current_time = now.time()
        
        # ALL_WEEK_SCAN: Her gün 00:00-07:00 arası tarama
        if self.config["ALL_WEEK_SCAN"]:
            return self.config["ALL_WEEK_START"] <= current_time < self.config["ALL_WEEK_END"]
        
        # WEEKEND_SCAN: Cumartesi 00:10'dan Pazartesi 07:00'a kadar tarama
        if self.config["WEEKEND_SCAN"]:
            # Cumartesi (5): 00:10'dan sonra
            if weekday == 5:
                return current_time >= self.config["WEEKEND_START"]
            # Pazar (6): Tüm gün
            elif weekday == 6:
                return True
            # Pazartesi (0): 07:00'a kadar
            elif weekday == 0:
                return current_time < self.config["WEEKEND_END"]
                
        return False

    def _calculate_next_sleep(self):
        """Çalışma penceresi dışındaysa bir sonraki başlangıca kadar, içindeyse sabit aralık kadar saniye döner."""
        if self._is_running_window():
            return self.config["LOOP_SLEEP_INTERVAL"]
        
        # Akıllı bekleme: Bir sonraki pencereye kadar uyu
        now = datetime.datetime.now()
        today = now.date()
        next_possible_start_times = []

        for i in range(7): # Bir hafta boyunca kontrol et
            day_to_check = today + datetime.timedelta(days=i)
            weekday = day_to_check.weekday()
            
            # ALL_WEEK_SCAN: Her gün başlangıcı
            if self.config["ALL_WEEK_SCAN"]:
                start_time = self.config["ALL_WEEK_START"]
            # WEEKEND_SCAN: Sadece Cumartesi başlangıcı
            elif weekday == 5 and self.config["WEEKEND_SCAN"]:
                start_time = self.config["WEEKEND_START"]
            else:
                continue
            
            next_start_dt = datetime.datetime.combine(day_to_check, start_time)
            if next_start_dt > now:
                next_possible_start_times.append(next_start_dt)

        if not next_possible_start_times:
            return 3600 # Hiç pencere bulunamazsa 1 saat uyu

        sleep_duration = (min(next_possible_start_times) - now).total_seconds()
        return max(1, sleep_duration) # En az 1 saniye uyu

    def _terminate_process(self):
        """Çalışan süreci sonlandırır."""
        if not self.current_process or self.current_process.poll() is not None:
            return

        logging.info("Çalışma penceresi bitti, mevcut süreç sonlandırılıyor...")
        try:
            pid = self.current_process.pid
            # Süreç grubuna sinyal göndererek alt süreçleri de kapatmayı dene
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            logging.info(f"Süreç grubuna (PGID: {os.getpgid(pid)}) SIGTERM gönderildi.")
        except (ProcessLookupError, OSError) as e:
            logging.warning(f"Süreç grubuna sinyal gönderilemedi (muhtemelen zaten kapanmış): {e}. PID {pid}'e gönderiliyor.")
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass # Zaten kapanmıs

        try:
            self.current_process.wait(timeout=15)
            logging.info("Süreç başarıyla sonlandırıldı.")
        except subprocess.TimeoutExpired:
            logging.warning("Süreç SIGTERM'e yanıt vermedi, zorla kapatılıyor (SIGKILL)...")
            os.killpg(os.getpgid(self.current_process.pid), signal.SIGKILL)
        
        self.current_process = None

    def _get_next_start_time(self):
        """Bir sonraki çalışma penceresinin başlangıç zamanını bulur."""
        now = datetime.datetime.now()
        
        for i in range(7): # Bir hafta boyunca kontrol et
            day_to_check = now.date() + datetime.timedelta(days=i)
            weekday = day_to_check.weekday()
            
            start_time = None
            # ALL_WEEK_SCAN: Her gün başlangıcı
            if self.config["ALL_WEEK_SCAN"]:
                start_time = self.config["ALL_WEEK_START"]
            # WEEKEND_SCAN: Sadece Cumartesi başlangıcı
            elif weekday == 5 and self.config["WEEKEND_SCAN"]:
                start_time = self.config["WEEKEND_START"]
            
            if start_time:
                next_start_dt = datetime.datetime.combine(day_to_check, start_time)
                if next_start_dt > now:
                    return next_start_dt
        return None # Uygun bir başlangıç bulunamadı

    def _get_current_window_end_time(self):
        """Mevcut çalışma penceresinin bitiş zamanını bulur."""
        now = datetime.datetime.now()
        weekday = now.weekday()
        
        # ALL_WEEK_SCAN: Her gün 07:00'da biter
        if self.config["ALL_WEEK_SCAN"]:
            end_dt = datetime.datetime.combine(now.date(), self.config["ALL_WEEK_END"])
            return end_dt if end_dt > now else None
        
        # WEEKEND_SCAN kontrolü
        if self.config["WEEKEND_SCAN"]:
            # Cumartesi: Pazartesi 07:00'a kadar devam eder
            if weekday == 5:
                end_day = now.date() + datetime.timedelta(days=2)  # Pazartesi
                return datetime.datetime.combine(end_day, self.config["WEEKEND_END"])
            # Pazar: Pazartesi 07:00'a kadar
            elif weekday == 6:
                end_day = now.date() + datetime.timedelta(days=1)  # Pazartesi
                return datetime.datetime.combine(end_day, self.config["WEEKEND_END"])
            # Pazartesi 07:00'a kadar hafta sonu penceresi
            elif weekday == 0:
                end_dt = datetime.datetime.combine(now.date(), self.config["WEEKEND_END"])
                return end_dt if end_dt > now else None
            
        return None

    def run(self):
        """Ana zamanlayıcı döngüsünü başlatır."""
        if not self.commands:
            logging.warning("Komut dosyasında çalıştırılacak komut bulunamadı.")
            return

        logging.info(f"Komut Zamanlayıcı Başlatıldı. {len(self.commands)} komut yüklendi.")

        while self.next_command_index < len(self.commands):
            try:
                now = datetime.datetime.now()
                is_running_window = self._is_running_window()

                if is_running_window:
                    if self.current_process is None:
                        self._start_next_command()
                    else:
                        # Süreç çalışıyor, kill zamanını göster
                        end_time = self._get_current_window_end_time()
                        if end_time:
                            remaining_time = end_time - now
                            logging.info(f"Mevcut komutun sonlandırılmasına kalan süre: {format_timedelta(remaining_time)}")

                elif self.current_process is not None: # Çalışma penceresi bitti VE süreç var
                    self._terminate_process()
                    logging.info("Süreç durduruldu. Bir sonraki çalışma zamanı bekleniyor.")
                
                # Her döngüde, eğer süreç çalışmıyorsa ve pencere dışındaysak, bir sonraki başlangıç zamanını logla
                if not self.current_process and not is_running_window:
                    next_start = self._get_next_start_time()
                    if next_start:
                        remaining_time = next_start - now
                        logging.info(f"Bir sonraki komutun başlamasına kalan süre: {format_timedelta(remaining_time)}")

                if self.current_process:
                    self._check_process_status()
                
                sleep_interval = self._calculate_next_sleep()
                logging.debug(f"{sleep_interval:.1f} saniye uyunuyor...")
                time.sleep(sleep_interval)

            except Exception as e:
                logging.critical(f"Ana döngüde beklenmedik bir hata oluştu: {e}", exc_info=True)
                break
        
        logging.info("Tüm komutlar tamamlandı. Betik sonlandırılıyor.")

    def _start_next_command(self):
        """Sıradaki komutu daha güvenli bir şekilde başlatır."""
        command_to_run = self.commands[self.next_command_index]
        try:
            # IYILEŞTIRME: shlex ile güvenli ayrıştırma ve shell=False kullanımı
            args = shlex.split(command_to_run)
            logging.info(f"--- KOMUT {self.next_command_index + 1}/{len(self.commands)} BAŞLATILIYOR ---")
            logging.info(f"Komut: {command_to_run}")
            
            with open(self.config["COMMAND_OUTPUT_LOG_FILE"], 'a', encoding='utf-8') as output_log:
                output_log.write(f"\n--- {datetime.datetime.now()} - Başlatılıyor: {command_to_run} ---\n")
                # preexec_fn=os.setsid, süreçleri kendi gruplarında başlatır, bu da onları toplu halde sonlandırmayı kolaylaştırır.
                self.current_process = subprocess.Popen(
                    args, stdout=output_log, stderr=output_log, text=True, shell=False, preexec_fn=os.setsid
                )
        except FileNotFoundError:
            logging.error(f"Komut '{args[0]}' bulunamadı. Atlanıyor.")
            self._advance_to_next_command()
        except Exception as e:
            logging.error(f"Komut '{command_to_run}' başlatılırken hata: {e}. Atlanıyor.")
            self._advance_to_next_command()

    def _check_process_status(self):
        """Çalışan sürecin durumunu kontrol eder."""
        return_code = self.current_process.poll()
        if return_code is not None:
            logging.info(f"--- KOMUT {self.next_command_index + 1}/{len(self.commands)} TAMAMLANDI (Kod: {return_code}) ---")
            if return_code != 0:
                logging.warning(f"Komut sıfır olmayan bir kodla tamamlandı (Kod: {return_code}).")
            
            self.current_process = None
            self._advance_to_next_command()

    def _advance_to_next_command(self):
        """İndeksi bir artırır ve durumu kaydeder."""
        self.next_command_index += 1
        self._save_state()

    def cleanup_on_exit(self):
        """Betik kapanırken çalışan temizlik fonksiyonu."""
        logging.info("Betik kapanıyor, temizlik yapılıyor...")
        if self.current_process:
            self._terminate_process()

def signal_handler(signum, frame):
    """SIGINT ve SIGTERM sinyallerini yakalayıp programı düzgünce kapatır."""
    logging.warning(f"Sinyal {signal.strsignal(signum)} alındı. Çıkış yapılıyor...")
    sys.exit(0)

def main():
    command_file = None
    if len(sys.argv) > 1:
        command_file = sys.argv[1]
        print(f"Komut dosyası kullanılıyor: {command_file}")
    else:
        print("Herhangi bir komut dosyası belirtilmedi. Varsayılan komutlar kullanılacak.")
    
    lock_fd = acquire_lock()
    if not lock_fd:
        sys.exit(1) # Hata zaten loglandı

    # Sinyal yakalayıcıları ve çıkış fonksiyonlarını ayarla
    atexit.register(lambda: release_lock(lock_fd))
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        scheduler = CommandScheduler(command_file)
        scheduler.run()
    except Exception as e:
        # Scheduler başlatılırken oluşabilecek kritik hatalar için (örn: config okuma)
        logging.critical(f"Scheduler başlatılamadı veya çalıştırılamadı: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()