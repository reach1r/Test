import os
import secrets
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.argon2 import Argon2
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFCMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import cmac
import base64
import time
import threading

# Komutu çalıştırmak için
os.system('pip freeze > requirements.txt')
os.system('pip install -r requirements.txt')

class BatSec:
    def __init__(self, ana_pencere):
        """
        Ana pencereyi ve bileşenlerini başlatır.
        """
        self.ana_pencere = ana_pencere
        ana_pencere.title("BatSec Dosya Şifreleme / Çözme Aracı")
        ana_pencere.geometry("625x350")

        self.dosya_yolu = tk.StringVar()
        self.sifre = tk.StringVar()
        self.sifre_goster = tk.BooleanVar()
        self.tema = tk.StringVar(value="Beyaz")  # Varsayılan tema
        self.dil = tk.StringVar(value="Türkçe")  # Varsayılan dil
        self.hata_mesajlari = {
            "Türkçe": {
                "dosya_secilmedi": "Lütfen bir dosya seçin.",
                "sifre_girilmedi": "Lütfen bir şifre girin.",
                "enc_uzanti": "Sadece .enc uzantılı dosyalar çözülebilir.",
                "sifreleme_hatasi": "Şifreleme hatası: {hata}.",
                "cozme_hatasi": "Çözme hatası: {hata}. Dosya bozulmuş veya şifre yanlış olabilir.",
                "sifre_cozme_basarisiz": "Şifre çözme başarısız. Lütfen doğru şifreyi girdiğinizden emin olun.",
                "zayif_sifre" : "Şifre çok zayıf. Lütfen daha güçlü bir şifre girin."
            },
            "English": {
                "dosya_secilmedi": "Please select a file.",
                "sifre_girilmedi": "Please enter a password.",
                "enc_uzanti": "Only .enc files can be decrypted.",
                "sifreleme_hatasi": "Encryption error: {hata}.",
                "cozme_hatasi": "Decryption error: {hata}. The file may be corrupted or the password is incorrect.",
                "sifre_cozme_basarisiz": "Decryption failed. Please ensure you have entered the correct password.",
                "zayif_sifre" : "The password is too weak. Please enter a stronger password."
            }
        }

        self._olustur_bilesenler()
        self._yerlestir_bilesenler()
        self.tema_degistir()
        self.dil_degistir()
        self.giris_sifre.bind("<KeyRelease>", self.sifre_degisti)



    def _olustur_bilesenler(self):
        self.etiket_dosya = ttk.Label(self.ana_pencere, text="Dosya Yolu:", font=("Arial", 12))
        self.giris_dosya = ttk.Entry(self.ana_pencere, textvariable=self.dosya_yolu, width=40, font=("Arial", 12))
        self.buton_dosya_sec = ttk.Button(self.ana_pencere, text="Dosya Seç", command=self.dosya_sec)

        self.etiket_sifre = ttk.Label(self.ana_pencere, text="Şifre:", font=("Arial", 12))
        self.giris_sifre = ttk.Entry(self.ana_pencere, textvariable=self.sifre, show="*", width=40, font=("Arial", 12))
        self.sifre_goster_kutusu = ttk.Checkbutton(self.ana_pencere, text="Şifreyi Göster", variable=self.sifre_goster, command=self.sifre_goster_degistir)
        self.sifre_gucu_etiketi = ttk.Label(self.ana_pencere, text="", font=("Arial", 10))

        self.buton_sifrele = ttk.Button(self.ana_pencere, text="Şifrele", command=self.thread_sifrele)
        self.buton_coz = ttk.Button(self.ana_pencere, text="Çöz", command=self.thread_coz)
        self.ilerleme = ttk.Progressbar(self.ana_pencere, orient="horizontal", mode="determinate")

        self.tema_etiketi = ttk.Label(self.ana_pencere, text="Tema:", font=("Arial", 12))
        self.tema_secimi = ttk.Combobox(self.ana_pencere, textvariable=self.tema, values=["Beyaz", "Karanlık"], state="readonly")
        self.tema_secimi.bind("<<ComboboxSelected>>", self.tema_degistir)

        self.dil_etiketi = ttk.Label(self.ana_pencere, text="Dil:", font=("Arial", 12))
        self.dil_secimi = ttk.Combobox(self.ana_pencere, textvariable=self.dil, values=["Türkçe", "English"], state="readonly")
        self.dil_secimi.bind("<<ComboboxSelected>>", self.dil_degistir)



    def _yerlestir_bilesenler(self):
        """Arayüz bileşenlerini yerleştirir."""
        self.etiket_dosya.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.giris_dosya.grid(row=0, column=1, padx=10, pady=5)
        self.buton_dosya_sec.grid(row=0, column=2, padx=10, pady=5)
        
        self.etiket_sifre.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.giris_sifre.grid(row=1, column=1, padx=10, pady=5)
        self.sifre_goster_kutusu.grid(row=1, column=2, padx=10, pady=5)
        self.sifre_gucu_etiketi.grid(row=2, column=1, padx=10, pady=2, sticky="w")

        self.buton_sifrele.grid(row=3, column=0, columnspan=3, pady=10)
        self.buton_coz.grid(row=4, column=0, columnspan=3, pady=10)
        self.ilerleme.grid(row=5, column=0, columnspan=3, pady=10)

        self.tema_etiketi.grid(row=6, column=0, padx=10, pady=5, sticky="w")
        self.tema_secimi.grid(row=6, column=1, padx=10, pady=5)
        self.dil_etiketi.grid(row=7, column=0, padx=10, pady=5, sticky="w")
        self.dil_secimi.grid(row=7, column=1, padx=10, pady=5)



    def dil_degistir(self, event=None):
        """
        Arayüzde kullanılan dili değiştirir.
        """
        dil = self.dil.get()
        if dil == "Türkçe":
            self._ayarla_dil_turkce()
        else:
            self._ayarla_dil_ingilizce()



    def _ayarla_dil_turkce(self):
        """Türkçe metinleri ayarlar."""
        self.ana_pencere.title("BatSec Dosya Şifreleme / Çözme Aracı")
        self.etiket_dosya.config(text="Dosya Yolu:")
        self.buton_dosya_sec.config(text="Dosya Seç")
        self.etiket_sifre.config(text="Şifre:")
        self.sifre_goster_kutusu.config(text="Şifreyi Göster")
        self.buton_sifrele.config(text="Şifrele")
        self.buton_coz.config(text="Çöz")
        self.tema_etiketi.config(text="Tema:")
        self.dil_etiketi.config(text="Dil:")
        self.tema_secimi.config(values=["Beyaz", "Karanlık"])



    def _ayarla_dil_ingilizce(self):
        """İngilizce metinleri ayarlar."""
        self.ana_pencere.title("BatSec File Encryption/Decryption Tool")
        self.etiket_dosya.config(text="File Path:")
        self.buton_dosya_sec.config(text="Select File")
        self.etiket_sifre.config(text="Password:")
        self.sifre_goster_kutusu.config(text="Show Password")
        self.buton_sifrele.config(text="Encrypt")
        self.buton_coz.config(text="Decrypt")
        self.tema_etiketi.config(text="Theme:")
        self.dil_etiketi.config(text="Language:")
        self.tema_secimi.config(values=["White", "Dark"])



    def sifre_gucu_hesapla(self, sifre: str) -> int:
        """
        Şifrenin gücünü hesaplar.
        """
        guc = 0
        if len(sifre) < 12:  # Minimum uzunluk kontrolü
            return 0  # Zayıf

        guc += len(sifre) * 5
        guc += 10 if any(c.islower() for c in sifre) else 0
        guc += 10 if any(c.isupper() for c in sifre) else 0
        guc += 10 if any(c.isdigit() for c in sifre) else 0
        guc += 20 if any(c in "!@#$%^&*()_+=-`~[]{};':\",./<>?" for c in sifre) else 0

        return min(guc, 100)
 


    def sifre_gucu_goster(self):
        """
        Şifrenin gücünü gösterir ve günceller.
        """
        sifre = self.sifre.get()
        dil = self.dil.get()  # Dil değişkenini al

        if not sifre:
            self.sifre_gucu_etiketi.config(text="")
            return

        guc = self.sifre_gucu_hesapla(sifre)
        metin, renk = self._belirle_guc_ve_renk(guc, dil)
        self.sifre_gucu_etiketi.config(text=metin, foreground=renk)


    def _belirle_guc_ve_renk(self, guc, dil):
        """
        Şifrenin gücüne ve dile göre metni ve rengi belirler.
        Args:
            guc (int): Şifrenin gücü.
            dil (str): Arayüz dili.
        Returns:
            tuple: Metin ve renk.
        """
        if guc < 30:  # 12 karakterden az
            if dil == "Türkçe":
                return "Zayıf", "red"
            return "Weak", "red"
        elif 30 <= guc < 100:  # 12-18 karakter arası
            if dil == "Türkçe":
                return "Orta", "orange"  # "Orta" seviyesi için renk
            return "Medium", "orange"
        else:  # 20 ve üzeri
            if dil == "Türkçe":
                return "Güçlü", "green"
            return "Strong", "green"


    def sifre_degisti(self, event):
        """
        Şifre değiştiğinde şifre gücünü günceller.
        """
        self.sifre_gucu_goster()



    def sifre_goster_degistir(self):
        """
        Şifre gösterme ayarını değiştirir.
        """
        if self.sifre_goster.get():
            self.giris_sifre.config(show="")
        else:
            self.giris_sifre.config(show="*")
        self.sifre_gucu_goster()    


    def donanimsal_rastgele_sayi_uret(self, length: int) -> bytes:
        """
        Donanımsal rastgele sayı üreteci kullanarak rastgele baytlar üretir.
        Args:
            length (int): Üretilecek bayt sayısı.
        Returns:
            bytes: Rastgele baytlar.
        """
        return os.urandom(length)


    def anahtar_olustur(self, sifre: str, tuz: bytes = None) -> tuple[bytes, bytes]:
        if tuz is None:
            tuz = self.donanimsal_rastgele_sayi_uret(16)

        # İlk katman: scrypt ile anahtar oluşturma
        kdf_scrypt = Scrypt(salt=tuz, length=32, n=2**18, r=16, p=4, backend=default_backend())
        anahtar_scrypt = kdf_scrypt.derive(sifre.encode())

        # İkinci katman: Argon2 ile işleme
        kdf_argon2 = Argon2(
            time_cost=2, 
            memory_cost=102400, 
            parallelism=8, 
            type=Argon2.Type.I, 
            salt=tuz
        )
        anahtar_argon2 = kdf_argon2.derive(anahtar_scrypt)

        # Üçüncü katman: PBKDF2HMAC ile işleme (SHA-512 kullanarak)
        kdf_pbkdf2 = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=tuz,
            iterations=100000,
            backend=default_backend()
        )
        anahtar_pbkdf2 = kdf_pbkdf2.derive(anahtar_argon2)

        # Dördüncü katman: Anahtar sarmalama (HMAC kullanarak, SHA-512 ile)
        wrapping_key = self.donanimsal_rastgele_sayi_uret(32)
        kdf_wrap = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=tuz,
            iterations=100000,
            backend=default_backend()
        )
        wrapped_key = kdf_wrap.derive(anahtar_pbkdf2)

        # Beşinci katman: SHA-3 ile işleme
        digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
        digest.update(wrapped_key)
        anahtar_sha3 = digest.finalize()

        # Altıncı katman: HKDF ile işleme (SHA-512 kullanarak)
        kdf_hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=tuz,
            info=b'hkdf-key-derivation',
            backend=default_backend()
        )
        anahtar_hkdf = kdf_hkdf.derive(anahtar_sha3)

        # Yedinci katman: CMAC ile işleme (AES-CMAC kullanarak)
        c = cmac.CMAC(algorithms.AES(wrapping_key), backend=default_backend())
        c.update(anahtar_hkdf)
        anahtar_cmac = c.finalize()

        # Sekizinci katman: Blake2b Hashing
        digest_blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=default_backend())
        digest_blake2b.update(anahtar_cmac)
        anahtar_blake2b = digest_blake2b.finalize()

        # Dokuzuncu katman: HKDF ve KBKDF kombinasyonu
        kdf_hkdf_final = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=tuz,
            info=b'hkdf-key-derivation-final',
            backend=default_backend()
        )
        anahtar_hkdf_final = kdf_hkdf_final.derive(anahtar_blake2b)

        kdf_kbkdf_final = KBKDFCMAC(
            algorithm=cmac.CMAC(algorithms.AES(wrapping_key)),
            length=32,
            salt=tuz,
            info=b'kbkdf-key-derivation-final',
            backend=default_backend()
        )
        final_key = kdf_kbkdf_final.derive(anahtar_hkdf_final)

        # Onuncu katman: Asimetrik Şifreleme (RSA)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        final_key_with_rsa = public_key.encrypt(
            final_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )

        # Güvenilir Zaman Damgası ekleme
        timestamp = time.time()
        final_key_with_timestamp = final_key_with_rsa + str(timestamp).encode()

        # SHA-512/256 Hashing
        digest = hashes.Hash(hashes.SHA512_256(), backend=default_backend())
        digest.update(final_key_with_timestamp)
        final_hashed_key = digest.finalize()

        # Anahtarı base64 formatında döndür
        final_key_base64 = base64.urlsafe_b64encode(final_hashed_key)

        return final_key_base64, tuz


    def dosya_sec(self):
        """
        Kullanıcının bir dosya seçmesini sağlar ve dosya yolunu ayarlar.
        """
        self.dosya_yolu.set(filedialog.askopenfilename())



    def thread_sifrele(self):
        # İlerlemeyi başlat
        self.ilerleme.start()
        thread = threading.Thread(target=self.sifrele)
        thread.daemon = True
        thread.start()
        thread.join()
        # İlerlemeyi durdur
        self.ilerleme.stop()




    def thread_coz(self):
        # İlerlemeyi başlat
        self.ilerleme.start()
        thread = threading.Thread(target=self.coz)
        thread.daemon = True
        thread.start()
        thread.join()
        # İlerlemeyi durdur
        self.ilerleme.stop()
  



    def tema_degistir(self, event=None):
        """
        Arayüzün temasını değiştirir.
        Args:
            event: Olay tetikleyicisi (isteğe bağlı).
        """
        tema = self.tema.get()
        dil = self.dil.get()
        style = ttk.Style()
        
        if (tema == "Beyaz" and dil == "Türkçe") or (tema == "White" and dil == "English"):
            self.ana_pencere.config(bg="white")
            for widget in self.ana_pencere.winfo_children():
                if isinstance(widget, ttk.Label):
                    widget.config(background="white", foreground="black")
                elif isinstance(widget, ttk.Entry) or isinstance(widget, ttk.Combobox):
                    widget.config(background="white", foreground="black")
                elif isinstance(widget, ttk.Button) or isinstance(widget, ttk.Checkbutton):
                    widget.config(style="Light.TButton")
            style.configure("Light.TButton", background="lightgray", foreground="black", borderwidth=1, relief="groove", padding=(8, 4), font=('Arial', 10))
        else:
            self.ana_pencere.config(bg="gray15")
            for widget in self.ana_pencere.winfo_children():
                if isinstance(widget, ttk.Label):
                    widget.config(background="gray15", foreground="white")
                elif isinstance(widget, ttk.Entry) or isinstance(widget, ttk.Combobox):
                    widget.config(background="gray25", foreground="black")  # Metin rengi siyah yapıldı
                elif isinstance(widget, ttk.Button) or isinstance(widget, ttk.Checkbutton):
                    widget.config(style="Dark.TButton")
            style.configure("Dark.TButton", background="gray35", foreground="black", borderwidth=1, relief="groove", padding=(8, 4), font=('Arial', 10))



    def sifrele(self):
        if not self.hata_kontrol():
            return

        cikis_yolu = filedialog.askdirectory(title="Çıkış Klasörünü Seçin")
        dosya_yolu = self.dosya_yolu.get()
        sifre = self.sifre.get()

        if not cikis_yolu:
            return

        try:
            anahtar, tuz = self.anahtar_olustur(sifre)
            iv_aes = self.donanimsal_rastgele_sayi_uret(12)  # AES-GCM için 12 bayt IV
            iv_chacha = self.donanimsal_rastgele_sayi_uret(12)  # ChaCha20 için 12 bayt IV
            iv_blowfish = self.donanimsal_rastgele_sayi_uret(8)  # Blowfish için 8 bayt IV
            iv_camellia = self.donanimsal_rastgele_sayi_uret(16)  # Camellia için 16 bayt IV
            iv_serpent = self.donanimsal_rastgele_sayi_uret(16)  # Serpent için 16 bayt IV
            iv_twofish = self.donanimsal_rastgele_sayi_uret(16)  # Twofish için 16 bayt IV
            iv_rc6 = self.donanimsal_rastgele_sayi_uret(16)  # RC6 için 16 bayt IV
            iv_gost = self.donanimsal_rastgele_sayi_uret(16)  # GOST için 16 bayt IV
            iv_idea = self.donanimsal_rastgele_sayi_uret(16)  # IDEA için 16 bayt IV
            iv_mars = self.donanimsal_rastgele_sayi_uret(16)  # Mars için 16 bayt IV

            # İlk katman: AES-GCM
            cipher_aes = Cipher(algorithms.AES(anahtar), modes.GCM(iv_aes), backend=default_backend()).encryptor()
            with open(dosya_yolu, 'rb') as dosya:
                veri = dosya.read()
            sifrelenmis_veri = cipher_aes.update(veri) + cipher_aes.finalize()
            tag_aes = cipher_aes.tag

            # İkinci katman: ChaCha20 (12 bayt nonce gereksinimi ile)
            cipher_chacha = Cipher(algorithms.ChaCha20(anahtar, iv_chacha), mode=None, backend=default_backend()).encryptor()
            sifrelenmis_veri = cipher_chacha.update(sifrelenmis_veri) + cipher_chacha.finalize()

            # Üçüncü katman: Blowfish (CBC)
            cipher_blowfish = Cipher(algorithms.Blowfish(anahtar), modes.CBC(iv_blowfish), backend=default_backend()).encryptor()
            padder = padding.PKCS7(algorithms.Blowfish.block_size).padder()
            padded_data = padder.update(sifrelenmis_veri) + padder.finalize()
            sifrelenmis_veri = cipher_blowfish.update(padded_data) + cipher_blowfish.finalize()

            # Dördüncü katman: Camellia (CBC)
            cipher_camellia = Cipher(algorithms.Camellia(anahtar), modes.CBC(iv_camellia), backend=default_backend()).encryptor()
            padder = padding.PKCS7(algorithms.Camellia.block_size).padder()
            padded_data = padder.update(sifrelenmis_veri) + padder.finalize()
            sifrelenmis_veri = cipher_camellia.update(padded_data) + cipher_camellia.finalize()

            # Beşinci katman: Serpent (CBC)
            cipher_serpent = Cipher(algorithms.Serpent(anahtar), modes.CBC(iv_serpent), backend=default_backend()).encryptor()
            padder = padding.PKCS7(algorithms.Serpent.block_size).padder()
            padded_data = padder.update(sifrelenmis_veri) + padder.finalize()
            sifrelenmis_veri = cipher_serpent.update(padded_data) + cipher_serpent.finalize()

            # Altıncı katman: Twofish (CBC)
            cipher_twofish = Cipher(algorithms.Twofish(anahtar), modes.CBC(iv_twofish), backend=default_backend()).encryptor()
            padder = padding.PKCS7(algorithms.Twofish.block_size).padder()
            padded_data = padder.update(sifrelenmis_veri) + padder.finalize()
            sifrelenmis_veri = cipher_twofish.update(padded_data) + cipher_twofish.finalize()

            # Yedinci katman: RC6 (CBC)
            cipher_rc6 = Cipher(algorithms.RC6(anahtar), modes.CBC(iv_rc6), backend=default_backend()).encryptor()
            padder = padding.PKCS7(algorithms.RC6.block_size).padder()
            padded_data = padder.update(sifrelenmis_veri) + padder.finalize()
            sifrelenmis_veri = cipher_rc6.update(padded_data) + cipher_rc6.finalize()

            # Sekizinci katman: GOST (CBC)
            cipher_gost = Cipher(algorithms.GOST(anahtar), modes.CBC(iv_gost), backend=default_backend()).encryptor()
            padder = padding.PKCS7(algorithms.GOST.block_size).padder()
            padded_data = padder.update(sifrelenmis_veri) + padder.finalize()
            sifrelenmis_veri = cipher_gost.update(padded_data) + cipher_gost.finalize()

            # Dokuzuncu katman: IDEA (CBC)
            cipher_idea = Cipher(algorithms.IDEA(anahtar), modes.CBC(iv_idea), backend=default_backend()).encryptor()
            padder = padding.PKCS7(algorithms.IDEA.block_size).padder()
            padded_data = padder.update(sifrelenmis_veri) + padder.finalize()
            sifrelenmis_veri = cipher_idea.update(padded_data) + cipher_idea.finalize()

            # Onuncu katman: Mars (CBC)
            cipher_mars = Cipher(algorithms.Mars(anahtar), modes.CBC(iv_mars), backend=default_backend()).encryptor()
            padder = padding.PKCS7(algorithms.Mars.block_size).padder()
            padded_data = padder.update(sifrelenmis_veri) + padder.finalize()
            sifrelenmis_veri = cipher_mars.update(padded_data) + cipher_mars.finalize()

            # HMAC etiketleri oluşturma (Birden fazla katman)
            iv_listesi = [iv_aes, iv_chacha, iv_blowfish, iv_camellia, iv_serpent, iv_twofish, iv_rc6, iv_gost, iv_idea, iv_mars]
            etiket_listesi = [tag_aes]  # GCM etiketi
            hmac_etiketi = self._hmac_etiketi_olustur(anahtar, tuz, iv_listesi, etiket_listesi, sifrelenmis_veri)

            # Dosyayı yazma
            sifreli_dosya_yolu = os.path.join(cikis_yolu, os.path.basename(dosya_yolu) + ".enc")
            with open(sifreli_dosya_yolu, 'wb') as sifreli_dosya:
                sifreli_dosya.write(tuz + iv_aes + tag_aes + iv_chacha + iv_blowfish + iv_camellia + iv_serpent + iv_twofish + iv_rc6 + iv_gost + iv_idea + iv_mars + sifrelenmis_veri)

            messagebox.showinfo("Başarılı", f"Dosya şifrelendi ve {sifreli_dosya_yolu} olarak kaydedildi.")
        except Exception as hata:
            messagebox.showerror("Hata", self.hata_mesajlari[self.dil.get()]["sifreleme_hatasi"].format(hata=hata))




    def _hmac_etiketi_olustur(self, anahtar, tuz, iv_listesi, etiket_listesi, sifrelenmis_veri):
        """
        HMAC etiketi oluşturur.
        Args:
            anahtar: Şifreleme anahtarı.
            tuz: Şifreleme için kullanılan tuz.
            iv_listesi: IV (Giriş Vektörleri) listesi.
            etiket_listesi: GCM etiketleri listesi.
            sifrelenmis_veri: Şifrelenmiş veri.
        Returns:
            bytes: HMAC etiketi.
        """
        h = hmac.HMAC(anahtar, hashes.SHA512(), backend=default_backend())  # SHA-512 kullanımı
        # Tuz, IV'ler, etiketler ve şifrelenmiş veriyi birleştir
        h.update(tuz + b''.join(iv_listesi) + b''.join(etiket_listesi) + sifrelenmis_veri)
        return h.finalize()




    def _sifrelenmis_dosya_yolu(self, dosya_yolu, cikis_yolu):
        """
        Şifrelenmiş dosya yolunu oluşturur.
        Args:
            dosya_yolu: Orijinal dosya yolu.
            cikis_yolu: Çıkış klasörü yolu.
        Returns:
            str: Şifrelenmiş dosya yolu.
        """
        return os.path.join(cikis_yolu, os.path.basename(dosya_yolu) + ".enc")


    
    def coz(self):
        if not self.hata_kontrol():
            return

        cikis_yolu = filedialog.askdirectory(title="Çıkış Klasörünü Seçin")
        dosya_yolu = self.dosya_yolu.get()
        sifre = self.sifre.get()

        if not cikis_yolu:
            return

        if not dosya_yolu.lower().endswith(".enc"):
            messagebox.showerror("Hata", self.hata_mesajlari[self.dil.get()]["enc_uzanti"])
            return

        try:
            # Şifreli dosyayı oku
            tuz, iv_aes, tag_aes, iv_chacha, iv_blowfish, iv_camellia, iv_serpent, iv_twofish, iv_rc6, iv_gost, iv_idea, iv_mars, hmac_etiketi, sifrelenmis_veri = self._oku_sifreli_dosya(dosya_yolu)

            # Anahtar oluştur
            anahtar, _ = self.anahtar_olustur(sifre, tuz)

            # HMAC etiketini doğrula
            iv_listesi = [iv_aes, iv_chacha, iv_blowfish, iv_camellia, iv_serpent, iv_twofish, iv_rc6, iv_gost, iv_idea, iv_mars]
            etiket_listesi = [tag_aes]
            self._dogrula_hmac_etiketi(anahtar, tuz, iv_listesi, etiket_listesi, sifrelenmis_veri, hmac_etiketi)

            # Onuncu katman: Mars (CBC)
            cipher_mars = Cipher(algorithms.Mars(anahtar), modes.CBC(iv_mars), backend=default_backend()).decryptor()
            padded_data = cipher_mars.update(sifrelenmis_veri) + cipher_mars.finalize()
            unpadder = padding.PKCS7(algorithms.Mars.block_size).unpadder()
            sifrelenmis_veri = unpadder.update(padded_data) + unpadder.finalize()

            # Dokuzuncu katman: IDEA (CBC)
            cipher_idea = Cipher(algorithms.IDEA(anahtar), modes.CBC(iv_idea), backend=default_backend()).decryptor()
            padded_data = cipher_idea.update(sifrelenmis_veri) + cipher_idea.finalize()
            unpadder = padding.PKCS7(algorithms.IDEA.block_size).unpadder()
            sifrelenmis_veri = unpadder.update(padded_data) + unpadder.finalize()

            # Sekizinci katman: GOST (CBC)
            cipher_gost = Cipher(algorithms.GOST(anahtar), modes.CBC(iv_gost), backend=default_backend()).decryptor()
            padded_data = cipher_gost.update(sifrelenmis_veri) + cipher_gost.finalize()
            unpadder = padding.PKCS7(algorithms.GOST.block_size).unpadder()
            sifrelenmis_veri = unpadder.update(padded_data) + unpadder.finalize()

            # Yedinci katman: RC6 (CBC)
            cipher_rc6 = Cipher(algorithms.RC6(anahtar), modes.CBC(iv_rc6), backend=default_backend()).decryptor()
            padded_data = cipher_rc6.update(sifrelenmis_veri) + cipher_rc6.finalize()
            unpadder = padding.PKCS7(algorithms.RC6.block_size).unpadder()
            sifrelenmis_veri = unpadder.update(padded_data) + unpadder.finalize()

            # Altıncı katman: Twofish (CBC)
            cipher_twofish = Cipher(algorithms.Twofish(anahtar), modes.CBC(iv_twofish), backend=default_backend()).decryptor()
            padded_data = cipher_twofish.update(sifrelenmis_veri) + cipher_twofish.finalize()
            unpadder = padding.PKCS7(algorithms.Twofish.block_size).unpadder()
            sifrelenmis_veri = unpadder.update(padded_data) + unpadder.finalize()

            # Beşinci katman: Serpent (CBC)
            cipher_serpent = Cipher(algorithms.Serpent(anahtar), modes.CBC(iv_serpent), backend=default_backend()).decryptor()
            padded_data = cipher_serpent.update(sifrelenmis_veri) + cipher_serpent.finalize()
            unpadder = padding.PKCS7(algorithms.Serpent.block_size).unpadder()
            sifrelenmis_veri = unpadder.update(padded_data) + unpadder.finalize()

            # Dördüncü katman: Camellia (CBC)
            cipher_camellia = Cipher(algorithms.Camellia(anahtar), modes.CBC(iv_camellia), backend=default_backend()).decryptor()
            padded_data = cipher_camellia.update(sifrelenmis_veri) + cipher_camellia.finalize()
            unpadder = padding.PKCS7(algorithms.Camellia.block_size).unpadder()
            sifrelenmis_veri = unpadder.update(padded_data) + unpadder.finalize()

            # Üçüncü katman: Blowfish (CBC)
            cipher_blowfish = Cipher(algorithms.Blowfish(anahtar), modes.CBC(iv_blowfish), backend=default_backend()).decryptor()
            padded_data = cipher_blowfish.update(sifrelenmis_veri) + cipher_blowfish.finalize()
            unpadder = padding.PKCS7(algorithms.Blowfish.block_size).unpadder()
            sifrelenmis_veri = unpadder.update(padded_data) + unpadder.finalize()

            # İkinci katman: ChaCha20 (12 bayt nonce gereksinimi ile)
            cipher_chacha = Cipher(algorithms.ChaCha20(anahtar, iv_chacha), mode=None, backend=default_backend()).decryptor()
            sifrelenmis_veri = cipher_chacha.update(sifrelenmis_veri) + cipher_chacha.finalize()

            # İlk katman: AES-GCM
            cipher_aes = Cipher(algorithms.AES(anahtar), modes.GCM(iv_aes, tag_aes), backend=default_backend()).decryptor()
            decrypted_data = cipher_aes.update(sifrelenmis_veri) + cipher_aes.finalize()

            # Çözülmüş veriyi kaydet
            cozulmus_dosya_yolu = os.path.join(cikis_yolu, os.path.basename(dosya_yolu[:-4]))  # .enc uzantısını kaldır
            with open(cozulmus_dosya_yolu, 'wb') as cozulen_dosya:
                cozulen_dosya.write(decrypted_data)

            messagebox.showinfo("Başarılı", f"Dosya çözüldü ve {cozulmus_dosya_yolu} olarak kaydedildi.")
        except ValueError:
            messagebox.showerror("Hata", self.hata_mesajlari[self.dil.get()]["sifre_cozme_basarisiz"])
        except Exception as hata:
            messagebox.showerror("Hata", self.hata_mesajlari[self.dil.get()]["cozme_hatasi"].format(hata=hata))



    def hata_kontrol(self):
        if not self.dosya_yolu.get():
            self.hata_mesaji("dosya_secilmedi")
            return False

        if not self.sifre.get():
            self.hata_mesaji("sifre_girilmedi")
            return False

        if self.sifre_gucu_hesapla(self.sifre.get()) < 30:  # Zayıf şifre kontrolü
            self.hata_mesaji("zayif_sifre")
            return False

        return True



    def hata_mesaji(self, mesaj_kodu):
        mesaj = self.hata_mesajlari[self.dil.get()][mesaj_kodu]
        self.sifre_gucu_etiketi.config(text=mesaj, foreground="red")





    def _oku_sifreli_dosya(self, dosya_yolu):
        """
        Şifrelenmiş dosyayı okur ve bileşenlerini döndürür.
        Args:
            dosya_yolu: Şifrelenmiş dosya yolu.
        Returns:
            tuple: Tuz, IV'ler, etiketler, HMAC etiketi ve şifrelenmiş veri.
        """
        with open(dosya_yolu, 'rb') as sifreli_dosya:
            tuz = sifreli_dosya.read(16)  # Tuz
            iv_aes1 = sifreli_dosya.read(12)  # İlk AES için IV (12 bytes for AES-GCM)
            tag_aes1 = sifreli_dosya.read(16)  # İlk AES için etiket (16 bytes for AES-GCM tag)
            iv_chacha = sifreli_dosya.read(12)  # ChaCha20 için IV
            iv_blowfish = sifreli_dosya.read(8)  # Blowfish için IV
            iv_camellia = sifreli_dosya.read(16)  # Camellia için IV
            iv_serpent = sifreli_dosya.read(16)  # Serpent için IV
            iv_twofish = sifreli_dosya.read(16)  # Twofish için IV
            iv_rc6 = sifreli_dosya.read(16)  # RC6 için IV
            iv_gost = sifreli_dosya.read(16)  # GOST için IV
            iv_idea = sifreli_dosya.read(16)  # IDEA için IV
            iv_mars = sifreli_dosya.read(16)  # Mars için IV
            hmac_etiketi = sifreli_dosya.read(64)  # HMAC etiketi
            sifrelenmis_veri = sifreli_dosya.read()  # Şifrelenmiş veri

        return tuz, iv_aes1, tag_aes1, iv_chacha, iv_blowfish, iv_camellia, iv_serpent, iv_twofish, iv_rc6, iv_gost, iv_idea, iv_mars, hmac_etiketi, sifrelenmis_veri




    def _dogrula_hmac_etiketi(self, anahtar, tuz, iv_listesi, etiket_listesi, sifrelenmis_veri, hmac_etiketi):
        """
        HMAC etiketini doğrular.
        Args:
            anahtar: Şifreleme anahtarı.
            tuz: Şifreleme için kullanılan tuz.
            iv_listesi: Giriş vektörleri.
            etiket_listesi: GCM etiketleri.
            sifrelenmis_veri: Şifrelenmiş veri.
            hmac_etiketi: HMAC etiketi.
        Raises:
            ValueError: HMAC doğrulaması başarısız olursa.
        """
        h = hmac.HMAC(anahtar, hashes.SHA512(), backend=default_backend())  # SHA-512 kullanımı
        # Tuz, IV'ler, etiketler ve şifrelenmiş veriyi birleştir
        h.update(tuz + b''.join(iv_listesi) + b''.join(etiket_listesi) + sifrelenmis_veri)
        h.verify(hmac_etiketi)








if __name__ == "__main__":
    ana_pencere = tk.Tk()
    BatSec(ana_pencere)
    ana_pencere.mainloop()

