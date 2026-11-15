#!/usr/bin/env bash
# Zero-Timing Core: Экспресс-приёмка и диагностика Dell PowerEdge R730 (Bare-Metal)
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[!] Запустите с правами root: sudo $0"
  exit 1
fi

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

echo -e "\n[3] ШИНА PCIe, NUMA-ПРИВЯЗКА СЛОТОВ И УСКОРИТЕЛИ (X520-DA2 / TESLA P40)"
for dev in $(lspci -D | grep -iE "82599|X520|NVIDIA|Tesla" | awk '{print $1}'); do
  NODE=$(cat "/sys/bus/pci/devices/$dev/numa_node" 2>/dev/null || echo "-1")
  DESC=$(lspci -s "$dev" | cut -d' ' -f2-)
  LNK=$(lspci -vv -s "$dev" 2>/dev/null | grep "LnkSta:" | head -n1 | sed 's/^[[:space:]]*//')
  echo "PCIe $dev [NUMA Node: $NODE] -> $DESC"
  echo "     $LNK"
done

if command -v nvidia-smi &>/dev/null; then
  echo "--- Статус NVIDIA GPU ---"
  nvidia-smi --query-gpu=name,pci.bus_id,memory.total,temperature.gpu,pstate --format=csv,noheader || echo "[!] GPU не инициализирована"
fi

echo -e "\n[4] СЕТЕВЫЕ ПОРТЫ 10GbE (IXGBE / XDP_DRV)"
for iface in /sys/class/net/*; do
  NAME=$(basename "$iface")
  [[ "$NAME" == "lo" ]] && continue
  DRV=$(basename "$(readlink -f "$iface/device/driver" 2>/dev/null)" 2>/dev/null || echo "virtual")
  if [[ "$DRV" == "ixgbe" || "$DRV" == "i40e" || "$DRV" == "mlx5_core" ]]; then
    STATE=$(cat "$iface/operstate" 2>/dev/null || echo "unknown")
    NUMA=$(cat "$iface/device/numa_node" 2>/dev/null || echo "-1")
    echo "NIC $NAME (driver: $DRV, state: $STATE, NUMA Node: $NUMA)"
    ethtool -l "$NAME" 2>/dev/null | grep -E "Combined:" || true
  fi
done

echo -e "\n[5] BMC / iDRAC: ПРОВЕРКА ОШИБОК ECC И ТИХИЙ ПРОФИЛЬ КУЛЕРОВ (18%)"
modprobe ipmi_devintf 2>/dev/null || true
modprobe ipmi_si 2>/dev/null || true
if command -v ipmitool &>/dev/null && ipmitool mc info &>/dev/null; then
  echo "iDRAC BMC связь    : OK"
  ECC_ERR=$(ipmitool sel list 2>/dev/null | grep -iE "ECC|Memory|Voltage|Critical" | tail -n 5 || true)
  if [[ -n "$ECC_ERR" ]]; then
    echo "[!] Найдены записи в журнале SEL iDRAC:"
    echo "$ECC_ERR"
  else
    echo "Журнал SEL (ECC)   : критических ошибок памяти не обнаружено [OK]"
  fi
  echo "Отключаем разгон кулеров под сторонние PCIe-карты и ставим 18% PWM..."
  ipmitool raw 0x30 0xce 0x00 0x16 0x05 0x00 0x00 0x00 0x05 0x00 0x01 0x00 0x00 &>/dev/null || true
  ipmitool raw 0x30 0x30 0x01 0x00 &>/dev/null || true
  ipmitool raw 0x30 0x30 0x02 0xff 0x12 &>/dev/null || true
  ipmitool sdr type Temperature 2>/dev/null | grep -E "Inlet|Exhaust|Temp" | head -n 6 || true
else
  echo "[!] IPMI недоступен (проверьте модули ipmi_si или настройки iDRAC)"
fi

echo -e "\n======================================================================"
echo " ПРОВЕРКА ЗАВЕРШЕНА. ГОТОВО К РАЗВЁРТЫВАНИЮ ZERO-TIMING-CORE."
echo "======================================================================"
