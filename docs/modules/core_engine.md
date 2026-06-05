# Core Engine Modülü

Rust tabanlı yüksek performanslı port tarama motoru.

## Özellikler
- Ham soket (raw socket) yönetimi ile sıfır paket kaçırma
- Çok iş parçacıklı (multi-threaded) eş zamanlı tarama
- JSON formatında yapılandırılmış çıktı
- Timeout ve hata yönetimi

## Kullanım
```bash
./core_engine <hedef_ip> --ports <port_aralığı>
```

## Çıktı Formatı
```json
{
  "target": "192.168.1.1",
  "open_ports": [22, 80, 443],
  "scan_duration_ms": 1200
}
```
