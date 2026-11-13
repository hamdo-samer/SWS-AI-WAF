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
etiketlere göre dengeli biçimde ayrılır; TF-IDF yalnızca eğitim bölümünde
öğrenilir. TensorFlow destekli, uyumlu bir Python ortamında:

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
