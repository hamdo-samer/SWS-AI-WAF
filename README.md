# Smart Web Shield (sws) — Akıllı Web Güvenliği

Türkçe arayüzlü, eğitim amacı taşıyan yerel web isteği inceleme prototipi. İstek metaverisini açıklanabilir kurallarla puanlar; sonuçları SQLite veritabanına kaydeder ve panelde özetler.
AI model tahminleri danışma amaçlıdır; istek kararını yalnızca kural motoru belirler.

## Gereksinimler

- Python 3.10+
- Flask (`pip install -r requirements.txt`)

## Çalıştırma

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Tarayıcıda `http://127.0.0.1:5000` adresini açın. İstek inceleme formuna yol, yöntem ve isteğe bağlı metaveri girin. Sonuçlar `instance\firewall.sqlite3` içinde tutulur.

## Üretim yapılandırması

Kopyayı oluşturun:

```powershell
Copy-Item .env.example .env
```

Şunları ayarlayın:

- `SECRET_KEY`: uzun rastgele bir oturum imzalama anahtarı.
- `ADMIN_USERNAME` ve `ADMIN_PASSWORD_HASH`: Flask/Werkzeug ile üretilen yönetici parola hash'i.
- `DASHBOARD_PORT`: varsayılan 5000.
- `PROXY_PORT`: varsayılan 8081.
- `BACKEND_URL`: Proxy'nin yönlendireceği backend adresi.
- `DATABASE_URL`: SQLite yolu veya `postgresql://...` bağlantı adresi.
- `TRUSTED_PROXY_CIDRS`: `X-Forwarded-For` tespitine izin verilen yalnızca güvenilir proxy ağları.

Parola hash'i üretmek için:

```powershell
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash(input('Yeni parola: ')))"
```

Dashboard rotaları oturum tabanlı girişle korunur; `/panel`, `/gunluk`, `/api/ozet` ve export rotaları için giriş gerekir.

Canlı proxy demosu için, `http://127.0.0.1:8080` adresinde erişilebilir bir upstream
site varken `python proxy_app.py` çalıştırın. Proxy, upstream'e iletmeden önce yol,
sorgu ve en fazla 1 MiB'lık istek gövdesini kural motoruyla inceler. AI tahmini
danışma amaçlıdır; model çalışmazsa hata günlüğe kaydedilir ve karar kural motorunda
kalır. `app.py` ile `proxy_app.py` varsayılan olarak aynı portu (5000) kullandığından,
ikisini aynı anda çalıştırmak için port yapılandırmasını ayrıca değiştirmek gerekir.

## Sayfalar

- `/` — isteği manuel inceleme
- `/panel` — toplam, izin verilen ve engellenen incelemeler
- `/gunluk` — son 200 inceleme kaydı
- `/simulasyon` — örnek SQLi/XSS/CMDi metinlerini yerel olarak inceleme; komut veya ağ isteği çalıştırılmaz
- `/hakkinda` — kuralların ve sınırların açıklaması
- `/api/ozet` — JSON istatistik özeti
- `/export/csv` — son 1.000 kaydı CSV olarak indir
- `/export/pdf` — son 50 kaydı PDF olarak indir

## Testler

```powershell
python -m unittest discover -s tests -v
```

## Modelleri eğitme

`data/csic_database.csv` veri kümesi kullanılır. Eğitim ve test bölümleri
etiketlere göre dengeli biçimde ayrılmadan önce yinelenen normalize istekler tekilleştirilir;
çakışan etiketli istek grupları açıkça uyarılarak dışarıda bırakılır. TF-IDF sözlüğü,
CNN'in eğitim alt kümesinde öğrenilir; ayrılmış test verisi eğitimde kullanılmaz.
TensorFlow destekli, uyumlu bir Python ortamında:

```powershell
pip install -r requirements-training.txt
python train_models.py
```

Eğitim ve uygulama aynı `Method` ve normalize edilmiş `URL` metnini kullanır;
CSIC mutlak adresleri modelleme öncesi istek yoluna dönüştürülür.
Bu özellikler değişirse modelleri yeniden eğitin. Eğitim
`models/random_forest.joblib`, `models/vectorizer.joblib`,
`models/1d_cnn.keras` ve elde tutulan test bölümü için `models/metrics.json`
üretir. Modellerin karşılaştırması kontrol panelinde görünür. Ana uygulama
bağımlılıklarıyla RF modeli kullanılabilir; CNN için TensorFlow gerekir. Model
dosyalarını yalnızca güvendiğiniz kaynaktan yükleyin: joblib dosyaları Python
kodu çalıştırabilir. Modeller eğitilmemişse uygulama AI çıktısı uydurmaz.

Bu bir eğitim demosudur; ağ trafiğini yönlendirmez, gerçek sitelere istek göndermez ve üretim ortamında kullanılan bir web uygulaması güvenlik duvarının yerine geçmez. Canlıya almadan önce kimlik doğrulama, CSRF koruması, TLS, güvenlik testleri ve uzman incelemesi eklenmelidir.

## Docker ile çalıştırma

Önce `.env.example` dosyasını `.env` olarak kopyalayın ve yerel gizli anahtarları düzenleyin:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

- Dashboard: `http://127.0.0.1:5000`
- Proxy: `http://127.0.0.1:8081`
- Örnek backend: Docker Compose içindeki `backend` servisi
