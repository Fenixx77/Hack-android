# Hack-android. Что­бы не засорять фай­ловую сис­тему основно­го обра­за, луч­ше исполь­зовать для хра­нения исходных кодов ядра отдель­ный образ, который может менять­ся от телефо­на к телефо­ну. Пару шагов назад уже было про­демонс­три­рова­но соз­дание обра­за из фай­ла. И тут под­разуме­вает­ся, что нуж­но сде­лать то же самое, толь­ко вмес­то уста­нов­ки Linux в образ сле­дует ска­чать и рас­паковать исходни­ки ядра. Пос­ле чего допол­нитель­ный образ мон­тиру­ется уже при­выч­ным спо­собом из Android-окру­жения в каталог chroot-окру­жения:

mount -o loop kernel.img /data/linux/usr/src/linux
Как толь­ко опре­делен драй­вер, который нуж­но соб­рать, необ­ходимо запус­тить ком­пиляцию толь­ко одно­го выб­ранно­го модуля (плюс его воз­можных зависи­мос­тей):

make menuconfig
make modules M=path/to/component
make modules_install
За­меть, тут не про­исхо­дит ком­пиляции всех модулей и уж тем более не переком­пилиру­ется все ядро. В этом слу­чае собира­ется толь­ко один необ­ходимый модуль и его воз­можные зависи­мос­ти.

Итак, вот при­мер­ный уни­вер­саль­ный алго­ритм сбор­ки драй­вера. На ноут­буке с Linux запус­кает­ся коман­да

udevadm monitor
э

Dirtycow (CVE-2016-5195)
 Основная атака в dirtycow для Android — подмена /system/bin/run-as — подобие sudo для отладки приложений. Начиная с API android-19 (таблица соответствия версий API и Android) /system/bin/run-as имеет CAP_SETUID и CAP_SETGID capabilities флаги (в старых версиях используется обычный suid bit — 6755).


$ getcap bin/run-as 
bin/run-as = cap_setgid,cap_setuid+ep

Если файловая система будет примонтирована в режиме read-write, то всё, что dirtycow подменяет, окажется на файловой системе. Потому необходимо сделать backup оригинального файла и восстановить его после получения доступа, либо не перемонтировать файловую систему в режиме read-write. Как правило раздел /system в Android по умолчанию примонтирован в режиме read-only.


adbd и консоль
$ capsh --decode=0000001fffffffff



Просмотр context'а файлов: ls -Z
Просмотр context'а запущенных процессов: ps -Z


Получаем root доступ

$ dd if=/dev/block/mmcblk0 of=/storage/sdcard1/mmcblk0.img
$ dd if=/dev/block/platform/msm_sdcc.1/by-name/boot of=/storage/sdcard1/boot.img
$ dd if=/dev/block/platform/msm_sdcc.1/by-name/recovery of=/storage/sdcard1/recovery.img
Команда kpartx -a mmbblk0.img создает виртуальное блочное устройство, доступное по пути /dev/m


$ grep -A2 reload_policy boot/ramfs/init.rc 
on property:selinux.reload_policy=1
    restart ueventd
    restart installd



Для начала нужно выяснить что из себя представляет /sepolicy. Изучить его можно с помощью команды sesearch (пакет setools в Debian).


$ sesearch --allow sepolicy
$ sesearch --neverallow sepolicy
$ sesearch --auditallow sepolicy
$ sesearch --dontaudit sepolicy


$ sesearch --allow sepolicy | grep 'load_policy'
   allow init kernel : security load_policy ;

Моей задачей было — разрешить init контексту задать selinux->enforce в permissive (setenforce 0).


adb shell run-as /data/local/tmp/run -u system -c u:r:init:s0 load_policy /data/local/tmp/sepolicy.new


Копаем recovery

image

java -jar dumpkey.jar android/bootable/recovery/testdata/testkey.x509.pem > mykey
diff -u mykey res/keys


$ grep mmcblk1 recovery/ramfs/etc/recovery.fstab 
/dev/block/mmcblk1p1                              /sdcard           vfat    nosuid,nodev,barrier=1,data=ordered,nodelalloc                  wait



hooks


adb reboot bootloader — режим fastboot, в моём телефоне не доступен (0x77665500 — hex метка 00556677 в разделе sbl1)
adb reboot recovery — режим recovery (0x77665502 — hex метка 02556677 в разделе sbl1)
adb reboot rtc — так называемый ALARM_BOOT.
Встроенный ROM загрузчик Qualcomm (pbl — primary bootloader) загружает раздел sbl1 (secondary bootloader). sbl1 загружает tz (trust zone), затем aboot (android boot, little kernel, lk). Aboot в свою очередь загружает boot, recovery или fota.


Описание разделов, участвующих при загрузке:


tz — Qualcomm Trust Zone. Выполняет низкоуровневые операции, в том числе работает с QFuses (раздел rpmb).
rpm — Resource and Power Manager firmware. Прошивка для специализированного SoC, отвечающего за ресурсы и питание.
sdi — trust zone storage partition. Данные, которые используются Trust Zone.


FOTA — firmware over the air. В отличие от boot и recovery, : 




#!/system/bin/sh
echo 0 > /proc/sys/kernel/dmesg_restrict



Патченный adbd

image




$ unpackbootimg -i boot.img -o boot
$ extract-symvers.py -e le -B 0xc0008000 boot/boot.img-zImage > %PATH_TO_KERNEL%/Module.symvers



image




создаю symlink wlan.c на исходник модуля
правлю Makefile

...
MODULE_NAME = wlan
...


$ adb shell "grep kc_bootmode_setup /proc/kallsyms"
c0d19d84 t kc_bootmode_setup

Описываю функцию в модуле:


int (*_kc_bootmode_setup)(char *buf) = (int(*)()) 0xc0d19d84;

И вызываю её:


_kc_bootmode_setup("f-ksg")

Можно адреса найти динамически:


_kc_bootmode_setup = (int (*)(char *buf))kallsyms_lookup_name("kc_bootmode_setup");


void (*_reset_security_ops)(void) = NULL;
... ... ...
_reset_security_ops = (void (*)(void))kallsyms_lookup_name("reset_security_ops");
if (_reset_security_ops != NULL) {
  _reset_security_ops();
}


int (*_enable_dload_mode)(char *str) = (int(*)()) 
BS=512
nextblock=0
IMG=my-recovery.img
DEST=/dev/sdb12
# 64 - total amount of 512*512b blocks for 16Mb partition (16Mb*1024*1024/(512*512))
for i in {1..64}; do
  echo $i
  echo dd if=${IMG} of=${DEST} bs=${BS} seek=${nextblock} skip=${nextblock} count=${BS} oflag=direct
  dd if=${IMG} of=${DEST} bs=${BS} seek=${nextblock} skip=${nextblock} count=${BS} oflag=direct
  nextblock=$((nextblock+BS))
  echo "nextblock = ${nextblock}"
  sleep 0.5
done
sync
echo 3 > /proc/sys/vm/drop_caches



#!/bin/bash

# print der certificate:
# openssl x509 -inform der -in 0xff.crt -text -noout

# mkdir boot
# unpackbootimg -i 09-boot.img -o boot
# cd boot
# mkbootimg --kernel 09-boot.img-zImage --ramdisk 09-boot.img-ramdisk.gz --cmdline "`cat 09-boot.img-cmdline`" --base `cat 09-boot.img-base` --pagesize `cat 09-boot.img-pagesize` --dt 09-boot.img-dtb --kernel_offset `cat 09-boot.img-kerneloff` --ramdisk_offset `cat 09-boot.img-ramdiskoff` --tags_offset `cat 09-boot.img-tagsoff` --output mynew.img
# dd if=../09-boot.img of=signature.bin bs=1 count=256 skip=$(ls -la mynew.img | awk '{print $5}')
# cd ..
# binwalk -e 05-aboot.img

# extract aboot signature
# dd if=05-aboot.img of=signature.bin bs=1 count=256 skip=$(od -A d -t x4 05-aboot.img | awk --non-decimal-data '/^0000016/ { i=sprintf("%d\n","0x"$3); print (i+40)}')

# extract base aboot image
# 40 - aboot header size, refer to: https://android.googlesource.com/kernel/lk/+/caf/master/target/msm8226/tools/mkheader.c#160
# dd if=05-aboot.img of=aboot-base.img bs=1 count=$(od -A d -t x4 05-aboot.img | awk --non-decimal-data '/^0000016/ { i=sprintf("%d\n","0x"$3); print (i)}') skip=40
# how sha256 was calculated?
# openssl dgst -sha256 -sign private_key -out signature.bin aboot-base.img ?

NAME=$1
IMG=${NAME}/mynew.img
SIG=${NAME}/signature.bin

#IMG=aboot-base.img
#SIG=signature.bin

CALC_SHA256=$(sha256sum ${IMG} | awk '{print $1}')

for i in `find . -name *.crt`; do
  ORIG_SHA256=$(openssl rsautl -inkey <(openssl x509 -pubkey -noout -inform der -in ${i} 2>/dev/null) -pubin -in ${SIG} 2>/dev/null | hexdump -ve '/1 "%02x"')
  if [ "${ORIG_SHA256}" != "" ]; then
    echo "sha256 was decrypted using ${i} key - ${ORIG_SHA256}"
  fi
  if [ "${ORIG_SHA256}" = "${CALC_SHA256}" ]; then
    echo "sha256 ${ORIG_SHA256}"
    echo "$i"
  fi
done
 



