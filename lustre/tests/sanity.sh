!/bin/sh

echo '===============================' test 1
mkdir /mnt/lustre/d1
mkdir /mnt/lustre/d1/d2
sh llmountcleanup.sh
dmesg |' grep -i destruct
sh llmount.sh

echo '===============================' test 2
mkdir /mnt/lustre/d1
touch /mnt/lustre/d1/f
sh llmountcleanup.sh
dmesg | grep -i destruct
sh llmount.sh

echo '===============================' test 3
mkdir /mnt/lustre/d1
umount /mnt/lustre
sh ../utils/lconf --start 70 local.xml
touch /mnt/lustre/d1/f
sh llmountcleanup.sh
dmesg | grep -i destruct
sh llmount.sh

echo '===============================' test 4
mkdir /mnt/lustre/d1
umount /mnt/lustre
sh ../utils/lconf --start 70 local.xml
mkdir /mnt/lustre/d1/d2
sh llmountcleanup.sh
dmesg | grep -i destruct
sh llmount.sh

echo '===============================' test 5
mkdir /mnt/lustre/d1
mkdir /mnt/lustre/d1/d2
chmod 0666 /mnt/lustre/d1/d2
sh llmountcleanup.sh
dmesg | grep -i destruct
sh llmount.sh

echo '===============================' test 6
touch /mnt/lustre/f
chmod 0666 /mnt/lustre/f
sh llmountcleanup.sh
dmesg | grep -i destruct
sh llmount.sh

echo '===============================' test 7
mkdir /mnt/lustre/d
./mcreate /mnt/lustre/d/f
chmod 0666 /mnt/lustre/d/f
sh llmountcleanup.sh
dmesg | grep -i destruct
sh llmount.sh

echo '===============================' test 8
mkdir /mnt/lustre/d
touch /mnt/lustre/d/f
chmod 0666 /mnt/lustre/d/f
sh llmountcleanup.sh
dmesg | grep -i destruct
sh llmount.sh


echo '===============================' test 9
mkdir /mnt/lustre/d
mkdir /mnt/lustre/d/d2
mkdir /mnt/lustre/d/d2/d3
sh llmountcleanup.sh
dmesg | grep -i destruct
sh llmount.sh


echo '===============================' test 10
mkdir /mnt/lustre/d
mkdir /mnt/lustre/d/d2
touch /mnt/lustre/d/d2/f
sh llmountcleanup.sh
dmesg | grep -i destruct
sh llmount.sh

echo '===============================' test 11
mkdir /mnt/lustre/d
mkdir /mnt/lustre/d/d2
chmod 0666 /mnt/lustre/d/d2
chmod 0555 /mnt/lustre/d/d2
sh llmountcleanup.sh
dmesg | grep -i destruct
sh llmount.sh

echo '===============================' test 12
mkdir /mnt/lustre/d
touch /mnt/lustre/d/f
chmod 0666 /mnt/lustre/d/f
chmod 0555 /mnt/lustre/d/f
sh llmountcleanup.sh
dmesg | grep -i destruct
sh llmount.sh
