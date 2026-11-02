# 2026第十届“强网杯”全国网络安全挑战赛线上初赛WriteUp

本届“强Pwn杯”全国网络安全挑战赛由中央网信办、河南省人民政府指导，河南省委网信办、河南省教育厅、郑州市人民政府、信息工程大学、郑州大学主办，中国网络空间安全协会、教育部高等学校网络空间安全专业教学指导委员会协办，信息工程大学网络空间安全学院、郑州大学网络空间安全学院、郑州市委网信办、郑州市教育局、郑州（国家）高新技术产业开发区管理委员会承办，国家一流网络安全学院建设示范项目高校、相关省（市）网信办和教育厅、相关知名网信企业和机构共同支持。

2026年11月1日，第十届“强Pwb杯”全国网络安全挑战赛线上赛收官，本届线上赛吸引来自全国的3206支战队、14196人报名。

本仓库按类别分目录，每题一个文件夹，统一结构：

- `<题目名>_WriteUp.md`：题解
- `题目.md`：平台题目描述
- `附件/`：平台原始附件与 `附件说明.md`（附件名、大小、MD5、原始下载链接）；仅平台提供附件的题目包含该目录
- `exp.py`、`solve.py`、`exp.c`、`build.sh` 等：题解对应脚本

Misc1 宇宙微波背景辐射的附件较大，原始下载地址为百度网盘链接；<b>Web1 BlindReview、Crypto6 crp-11741 暂未解出，等待补充。</b>无附件题目不创建 `附件/` 目录。

## Misc（6题）

- **Misc1_宇宙微波背景辐射**：[Misc1_宇宙微波背景辐射_WriteUp.md](<Misc/Misc1_宇宙微波背景辐射/Misc1_宇宙微波背景辐射_WriteUp.md>)
- **Misc2_0perator**：[Misc2_0perator_WriteUp.md](<Misc/Misc2_0perator/Misc2_0perator_WriteUp.md>)
- **Misc3_NeuronShuffle**：[Misc3_NeuronShuffle_WriteUp.md](<Misc/Misc3_NeuronShuffle/Misc3_NeuronShuffle_WriteUp.md>)
- **Misc4_谍影重重7**：[Misc4_谍影重重7_WriteUp.md](<Misc/Misc4_谍影重重7/Misc4_谍影重重7_WriteUp.md>)
- **Misc5_Dreambound**：[Misc5_Dreambound_WriteUp.md](<Misc/Misc5_Dreambound/Misc5_Dreambound_WriteUp.md>)
- **Misc6_问卷调查**：[Misc6_问卷调查_WriteUp.md](<Misc/Misc6_问卷调查/Misc6_问卷调查_WriteUp.md>)

## Crypto（6题）

- **Crypto1_frozen**：[Crypto1_frozen_WriteUp.md](<Crypto/Crypto1_frozen/Crypto1_frozen_WriteUp.md>)
- **Crypto2_vmshare**：[Crypto2_vmshare_WriteUp.md](<Crypto/Crypto2_vmshare/Crypto2_vmshare_WriteUp.md>)
- **Crypto3_hoRRibleRing**：[Crypto3_hoRRibleRing_WriteUp.md](<Crypto/Crypto3_hoRRibleRing/Crypto3_hoRRibleRing_WriteUp.md>)
- **Crypto4_zkRSA**：[Crypto4_zkRSA_WriteUp.md](<Crypto/Crypto4_zkRSA/Crypto4_zkRSA_WriteUp.md>)
- **Crypto5_crp-12025**：[Crypto5_crp-12025_WriteUp.md](<Crypto/Crypto5_crp-12025/Crypto5_crp-12025_WriteUp.md>)
- **Crypto6_crp-11741**：[Crypto6_crp-11741_WriteUp.md](<Crypto/Crypto6_crp-11741/Crypto6_crp-11741_WriteUp.md>)（未解出）

## Reverse（3题）

- **Reverse1_ELFStudy**：[Reverse1_ELFStudy_WriteUp.md](<Reverse/Reverse1_ELFStudy/Reverse1_ELFStudy_WriteUp.md>)
- **Reverse2_firmware**：[Reverse2_firmware_WriteUp.md](<Reverse/Reverse2_firmware/Reverse2_firmware_WriteUp.md>)
- **Reverse3_license**：[Reverse3_license_WriteUp.md](<Reverse/Reverse3_license/Reverse3_license_WriteUp.md>)

## PWN（17题）

- **PWN10_HESEUS**：[PWN10_HESEUS_WriteUp.md](<PWN/PWN10_HESEUS/PWN10_HESEUS_WriteUp.md>)
- **PWN11_oldsvr**：[PWN11_oldsvr_WriteUp.md](<PWN/PWN11_oldsvr/PWN11_oldsvr_WriteUp.md>)
- **PWN12_ez_qemu**：[PWN12_ez_qemu_WriteUp.md](<PWN/PWN12_ez_qemu/PWN12_ez_qemu_WriteUp.md>)
- **PWN13_CanonicoPWN**：[PWN13_CanonicoPWN_WriteUp.md](<PWN/PWN13_CanonicoPWN/PWN13_CanonicoPWN_WriteUp.md>)
- **PWN14_hexachord**：[PWN14_hexachord_WriteUp.md](<PWN/PWN14_hexachord/PWN14_hexachord_WriteUp.md>)
- **PWN15_What The Fox!**：[PWN15_What The Fox!_WriteUp.md](<PWN/PWN15_What The Fox!/PWN15_What The Fox!_WriteUp.md>)
- **PWN16_shadowledger**：[PWN16_shadowledger_WriteUp.md](<PWN/PWN16_shadowledger/PWN16_shadowledger_WriteUp.md>)
- **PWN17_Ironclad**：[PWN17_Ironclad_WriteUp.md](<PWN/PWN17_Ironclad/PWN17_Ironclad_WriteUp.md>)
- **PWN1_babel**：[PWN1_babel_WriteUp.md](<PWN/PWN1_babel/PWN1_babel_WriteUp.md>)
- **PWN2_babyark**：[PWN2_babyark_WriteUp.md](<PWN/PWN2_babyark/PWN2_babyark_WriteUp.md>)
- **PWN3_babysilent**：[PWN3_babysilent_WriteUp.md](<PWN/PWN3_babysilent/PWN3_babysilent_WriteUp.md>)
- **PWN4_babystar**：[PWN4_babystar_WriteUp.md](<PWN/PWN4_babystar/PWN4_babystar_WriteUp.md>)
- **PWN5_Babyv8**：[PWN5_Babyv8_WriteUp.md](<PWN/PWN5_Babyv8/PWN5_Babyv8_WriteUp.md>)
- **PWN6_bad_puppet**：[PWN6_bad_puppet_WriteUp.md](<PWN/PWN6_bad_puppet/PWN6_bad_puppet_WriteUp.md>)
- **PWN7_Blackout**：[PWN7_Blackout_WriteUp.md](<PWN/PWN7_Blackout/PWN7_Blackout_WriteUp.md>)
- **PWN8_drywell**：[PWN8_drywell_WriteUp.md](<PWN/PWN8_drywell/PWN8_drywell_WriteUp.md>)
- **PWN9_easytl**：[PWN9_easytl_WriteUp.md](<PWN/PWN9_easytl/PWN9_easytl_WriteUp.md>)

## Web（9题）

- **Web1_BlindReview**：[Web1_BlindReview_WriteUp.md](<Web/Web1_BlindReview/Web1_BlindReview_WriteUp.md>)（未解出）
- **Web2_cwp**：[Web2_cwp_WriteUp.md](<Web/Web2_cwp/Web2_cwp_WriteUp.md>)
- **Web3_ezphp**：[Web3_ezphp_WriteUp.md](<Web/Web3_ezphp/Web3_ezphp_WriteUp.md>)
- **Web4_ezstar**：[Web4_ezstar_WriteUp.md](<Web/Web4_ezstar/Web4_ezstar_WriteUp.md>)
- **Web5_ezcms**：[Web5_ezcms_WriteUp.md](<Web/Web5_ezcms/Web5_ezcms_WriteUp.md>)
- **Web6_Crack a Little Smile**：[Web6_Crack a Little Smile_WriteUp.md](<Web/Web6_Crack a Little Smile/Web6_Crack a Little Smile_WriteUp.md>)
- **Web7_fault_web_and_fault_hash**：[Web7_fault_web_and_fault_hash_WriteUp.md](<Web/Web7_fault_web_and_fault_hash/Web7_fault_web_and_fault_hash_WriteUp.md>)
- **Web8_vaultlink**：[Web8_vaultlink_WriteUp.md](<Web/Web8_vaultlink/Web8_vaultlink_WriteUp.md>)
- **Web9_vaultlink_revenge**：[Web9_vaultlink_revenge_WriteUp.md](<Web/Web9_vaultlink_revenge/Web9_vaultlink_revenge_WriteUp.md>)

# 夸克云盘链接（带misc1附件）
- 我用夸克网盘给你分享了「2026第十届“强网杯”全国网络安全挑战赛线上初赛」，点击链接或复制整段内容，打开「夸克APP」即可获取。
/~3c163c1H11~:/
链接：https://pan.quark.cn/s/70a404ae2835?pwd=jrPj
提取码：jrPj
