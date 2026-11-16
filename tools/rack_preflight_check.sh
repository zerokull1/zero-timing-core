#!/usr/bin/env bash
# ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
# Zero-Timing Core: Экспресс-приёмка и диагностика Dell PowerEdge R730 (Bare-Metal)
# Использование:
#   sudo ./tools/rack_preflight_check.sh           # полная аппаратная диагностика
#   sudo ./tools/rack_preflight_check.sh --stress  # диагностика + 60с стресс-тест CPU/MCE
#   sudo ./tools/rack_preflight_check.sh --quiet   # перевести кулеры iDRAC в тихий режим (18%)
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[!] Запустите с правами root: sudo $0"
  exit 1
fi

DO_STRESS=0
DO_QUIET=0
for arg in "$@"; do
  [[ "$arg" == "--stress" ]] && DO_STRESS=1
  [[ "$arg" == "--quiet" ]] && DO_QUIET=1
done

echo "======================================================================"
echo " ZERO-TIMING CORE — ЭКСПРЕСС-ДИАГНОСТИКА СТОЙКИ DELL POWEREDGE R730"
echo "======================================================================"

echo -e "\n[1] ПЛАТФОРМА, BIOS И ПРОЦЕССОРЫ (INTEL XEON)"
dmidecode -s system-product-name 2>/dev/null || true
dmidecode -s bios-version 2>/dev/null || true
LC_ALL=C lscpu | grep -E "Model name:|Socket\(s\):|Core\(s\) per socket:|Thread\(s\) per core:|NUMA node\(s\):"
VMX_OK=$(grep -cw "vmx" /proc/cpuinfo || true)
echo "VT-x (vmx) потоков : $VMX_OK"
IOMMU_CNT=$(find /sys/kernel/iommu_groups/ -maxdepth 1 -mindepth 1 2>/dev/null | wc -l)
echo "IOMMU (VT-d) групп : $IOMMU_CNT $( [[ $IOMMU_CNT -gt 0 ]] && echo '[OK]' || echo '[!] ВКЛЮЧИТЬ VT-d В BIOS!' )"

modprobe msr 2>/dev/null || true
if rdmsr 0xc90 &>/dev/null; then
  echo "Intel CAT (L3 MSR) : ДОСТУПЕН (IA32_L3_MASK_0 = 0x$(rdmsr 0xc90)) [OK]"
else
  echo "Intel CAT (L3 MSR) : недоступен или не поддерживается этой моделью CPU"
fi

echo -e "\n[2] ПАМЯТЬ DDR4 ECC И NUMA-МАТРИЦА"
dmidecode -t memory | awk '
  /Memory Device$/ { size=""; loc=""; speed=""; type="" }
  /Size:/ && $2 != "No" { size=$2" "$3 }
  /Locator:/ && !/Bank/ { loc=$2 }
  /Type:/ && $2 != "Unknown" { type=$2 }
  /Configured Memory Speed:/ && $4 != "Unknown" { speed=$4" "$5 }
  /Rank:/ && size != "" { printf "  %-12s | %-8s | %-6s | %s\n", loc, size, type, speed }
'
echo "--- NUMA Топология ---"
numactl --hardware | grep -E "available:|node [0-9]+ cpus:|node [0-9]+ size:|node [0-9]+ free:"

echo -e "\n[3] ШИНА PCIe (LnkCap vs LnkSta), NUMA-СЛОТЫ И УСКОРИТЕЛИ"
for dev in $(lspci -D | grep -iE "82599|X520|NVIDIA|Tesla|PERC|MegaRAID" | awk '{print $1}'); do
  NODE=$(cat "/sys/bus/pci/devices/$dev/numa_node" 2>/dev/null || echo "-1")
  DESC=$(lspci -s "$dev" | cut -d' ' -f2-)
  CAP=$(lspci -vv -s "$dev" 2>/dev/null | grep "LnkCap:" | head -n1 | sed 's/^[[:space:]]*//')
  LNK=$(lspci -vv -s "$dev" 2>/dev/null | grep "LnkSta:" | head -n1 | sed 's/^[[:space:]]*//')
  echo "PCIe $dev [NUMA Node: $NODE] -> $DESC"
  [[ -n "$CAP" ]] && echo "     $CAP"
  [[ -n "$LNK" ]] && echo "     $LNK"
done

AER_ERR=$(dmesg | grep -iE "pcieport.*error|AER:|Uncorrected|Corrected" | tail -n 5 || true)
if [[ -n "$AER_ERR" ]]; then
  echo "[!] Обнаружены ошибки шины PCIe AER в dmesg:"
  echo "$AER_ERR"
else
  echo "Ошибки шины PCIe AER: не обнаружены [OK]"
fi

if command -v nvidia-smi &>/dev/null; then
  echo "--- Статус NVIDIA GPU ---"
  nvidia-smi --query-gpu=name,pci.bus_id,memory.total,temperature.gpu,pstate --format=csv,noheader || echo "[!] GPU не инициализирована"
fi

echo -e "\n[4] СЕТЕВЫЕ ПОРТЫ 10GbE (IXGBE / XDP_DRV) И SFP+ МОДУЛИ"
for iface in /sys/class/net/*; do
  NAME=$(basename "$iface")
  [[ "$NAME" == "lo" ]] && continue
  DRV=$(basename "$(readlink -f "$iface/device/driver" 2>/dev/null)" 2>/dev/null || echo "virtual")
  if [[ "$DRV" == "ixgbe" || "$DRV" == "i40e" || "$DRV" == "mlx5_core" ]]; then
    STATE=$(cat "$iface/operstate" 2>/dev/null || echo "unknown")
    NUMA=$(cat "$iface/device/numa_node" 2>/dev/null || echo "-1")
    echo "NIC $NAME (driver: $DRV, state: $STATE, NUMA Node: $NUMA)"
    ethtool -l "$NAME" 2>/dev/null | grep -E "Combined:" || true
    ethtool -m "$NAME" 2>/dev/null | grep -E "Identifier|Vendor name|Vendor PN|Laser wavelength|Module temperature" || true
  fi
done

echo -e "\n[5] BMC / iDRAC: ECC, БЛОКИ ПИТАНИЯ (PSU), БАТАРЕЯ RAID И ТЕМПЕРАТУРЫ"
modprobe ipmi_devintf 2>/dev/null || true
modprobe ipmi_si 2>/dev/null || true
if command -v ipmitool &>/dev/null && ipmitool mc info &>/dev/null; then
  echo "iDRAC BMC связь    : OK"
  ECC_ERR=$(ipmitool sel list 2>/dev/null | grep -iE "ECC|Memory|Voltage|Critical|CPU|Fan" | tail -n 8 || true)
  if [[ -n "$ECC_ERR" ]]; then
    echo "[!] Найдены записи в журнале SEL iDRAC:"
    echo "$ECC_ERR"
  else
    echo "Журнал SEL (ECC)   : критических ошибок не обнаружено [OK]"
  fi
  echo "--- Блоки питания (PSU) и батарейка RAID ---"
  ipmitool sdr type "Power Supply" 2>/dev/null || true
  ipmitool sdr type "Battery" 2>/dev/null || true
  echo "--- Датчики температуры ---"
  ipmitool sdr type Temperature 2>/dev/null | grep -E "Inlet|Exhaust|Temp" | head -n 6 || true

  if [[ $DO_QUIET -eq 1 ]]; then
    echo "Включаем тихий профиль кулеров iDRAC (18% PWM)..."
    ipmitool raw 0x30 0xce 0x00 0x16 0x05 0x00 0x00 0x00 0x05 0x00 0x01 0x00 0x00 &>/dev/null || true
    ipmitool raw 0x30 0x30 0x01 0x00 &>/dev/null || true
    ipmitool raw 0x30 0x30 0x02 0xff 0x12 &>/dev/null || true
  fi
else
  echo "[!] IPMI недоступен (проверьте модули ipmi_si или настройки iDRAC)"
fi

if [[ $DO_STRESS -eq 1 ]]; then
  echo -e "\n[6] ЭКСПРЕСС-ПРОГРЕВ CPU (60 СЕКУНД) И КОНТРОЛЬ MCE"
  if command -v stress-ng &>/dev/null; then
    stress-ng --cpu 0 --timeout 60s --metrics-brief
  else
    echo "[!] Утилита stress-ng не установлена, запускаю встроенный прогрев на 60с..."
    timeout 60s bash -c 'for i in $(seq 1 $(nproc)); do while :; do :; done & done; wait' || true
  fi
  MCE_ERR=$(dmesg | grep -iE "mce:|Machine check|throttl" | tail -n 5 || true)
  if [[ -n "$MCE_ERR" ]]; then
    echo "[!] Обнаружены MCE / троттлинг после нагрузки:"
    echo "$MCE_ERR"
  else
    echo "Контроль MCE / троттлинг: чисто [OK]"
  fi
  ipmitool sdr type Temperature 2>/dev/null | grep -E "Inlet|Exhaust|Temp" | head -n 6 || true
fi

echo -e "\n======================================================================"
echo " ПРОВЕРКА ЗАВЕРШЕНА. ГОТОВО К РАЗВЁРТЫВАНИЮ ZERO-TIMING-CORE."
echo "======================================================================"
