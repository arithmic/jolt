
use std::cmp::min;
use std::fmt;
use std::str::FromStr;
use ark_bn254::Fr as Scalar;
use ark_bn254::Fq as Fp;
use ark_ff::BigInteger;
use ark_ff::Field;
use ark_ff::PrimeField;
use num_bigint::BigUint;
// use num_bigint::BigUint;
// use num_bigint::ToBigInt;

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fqq{
    pub element: Scalar,
    pub limbs: [Fp; 3],
}

pub fn convert_from_3_limbs(limbs: Vec<Fp>) -> Scalar {
    let r = Scalar::from(BigUint::from(limbs[0].into_bigint()))
    + Scalar::from(2u8).pow([(125) as u64, 0, 0, 0]) * Scalar::from(limbs[1].into_bigint())
    + Scalar::from(2u8).pow([(250) as u64, 0, 0, 0]) * Scalar::from(limbs[2].into_bigint());
    r
}

pub fn convert_to_3_limbs(r: Scalar) -> [Fp; 3] {
    let mut limbs = [Fp::ZERO; 3];

    let mask = BigUint::from((1u128 << 125) - 1);

    limbs[0] = Fp::from(BigUint::from(r.into_bigint()) & mask.clone());

    limbs[1] = Fp::from((BigUint::from(r.into_bigint()) >> 125) & mask.clone());

    limbs[2] = Fp::from((BigUint::from(r.into_bigint()) >> 250) & mask.clone());

    limbs
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct FqLimb{
    pub limbs: [Fp; 3],
}

impl fmt::Debug for Fqq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{
            "element": "{}",
            "limbs": ["{}", "{}", "{}"]
            }}"#,
            self.element, &self.limbs[0], &self.limbs[1].to_string(), &self.limbs[2].to_string()
        )
    }
}

impl fmt::Debug for FqLimb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"[[
            "{}", "{}", "{}"
            ]]"#,
            self.limbs[0], self.limbs[1], self.limbs[2]
        )
    }
}

// impl fmt::Debug for FqLimb {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(
//             f,
//             r#"["{}", "{}", "{}"]"#,
//             hex_to_decimal(&self.limbs[0].to_string()),
//             hex_to_decimal(&self.limbs[1].to_string()),
//             hex_to_decimal(&self.limbs[2].to_string())
//         )
//     }
// }


// pub const LQ: [[Fp; 3]; 8] = [
//     [
//         Fp::ZERO,
//         Fp::ZERO,
//         Fp::ZERO,
//     ],
//     [  // a + q * 0
//     Fp::from(BigUint::from_str("10903342367192220456583066779700428801").clone().unwrap()),
//     Fp::from(BigUint::from_str("4166566524057721139834548734155997929").clone().unwrap()),
//     Fp::from(BigUint::from_str("12").clone().unwrap()),
//   ],
//   [  // a + q * 1
//   Fp::from(BigUint::from_str("21806684734384440913166133559400857602").clone().unwrap()),
//   Fp::from(BigUint::from_str("8333133048115442279669097468311995858").clone().unwrap()),
//   Fp::from(BigUint::from_str("24").clone().unwrap()),
//   ],
//   [  // a + q * 2
//   Fp::from(BigUint::from_str("32710027101576661369749200339101286403").clone().unwrap()),
//   Fp::from(BigUint::from_str("12499699572173163419503646202467993787").clone().unwrap()),
//   Fp::from(BigUint::from_str("36").clone().unwrap()),
//   ],
//   [  // a + q * 3
//   Fp::from(BigUint::from_str("1078073603651573893410441189830688772").clone().unwrap()),
//   Fp::from(BigUint::from_str("16666266096230884559338194936623991717").clone().unwrap()),
//   Fp::from(BigUint::from_str("48").clone().unwrap()),
//   ],
//   [  // a + q * 4
//   Fp::from(BigUint::from_str("11981415970843794349993507969531117573").clone().unwrap()),
//   Fp::from(BigUint::from_str("20832832620288605699172743670779989646").clone().unwrap()),
//   Fp::from(BigUint::from_str("60").clone().unwrap()),
//   ],
//   [  // a + q * 5
//   Fp::from(BigUint::from_str("22884758338036014806576574749231546374").clone().unwrap()),
//   Fp::from(BigUint::from_str("24999399144346326839007292404935987575").clone().unwrap()),
//   Fp::from(BigUint::from_str("72").clone().unwrap()),
//   ],
//   [  // a + q * 6
//   Fp::from(BigUint::from_str("33788100705228235263159641528931975175").clone().unwrap()),
//   Fp::from(BigUint::from_str("29165965668404047978841841139091985504").clone().unwrap()),
//   Fp::from(BigUint::from_str("84").clone().unwrap()),
//   ]
// ];

pub fn return_multiple_of_q(index: usize) -> [Fp; 3]{
    let  LQ: [[Fp; 3]; 8] = [
        [
            Fp::ZERO,
            Fp::ZERO,
            Fp::ZERO,
        ],
        [  // a + q * 0
        Fp::from(BigUint::from_str("10903342367192220456583066779700428801").clone().unwrap()),
        Fp::from(BigUint::from_str("4166566524057721139834548734155997929").clone().unwrap()),
        Fp::from(BigUint::from_str("12").clone().unwrap()),
      ],
      [  // a + q * 1
      Fp::from(BigUint::from_str("21806684734384440913166133559400857602").clone().unwrap()),
      Fp::from(BigUint::from_str("8333133048115442279669097468311995858").clone().unwrap()),
      Fp::from(BigUint::from_str("24").clone().unwrap()),
      ],
      [  // a + q * 2
      Fp::from(BigUint::from_str("32710027101576661369749200339101286403").clone().unwrap()),
      Fp::from(BigUint::from_str("12499699572173163419503646202467993787").clone().unwrap()),
      Fp::from(BigUint::from_str("36").clone().unwrap()),
      ],
      [  // a + q * 3
      Fp::from(BigUint::from_str("1078073603651573893410441189830688772").clone().unwrap()),
      Fp::from(BigUint::from_str("16666266096230884559338194936623991717").clone().unwrap()),
      Fp::from(BigUint::from_str("48").clone().unwrap()),
      ],
      [  // a + q * 4
      Fp::from(BigUint::from_str("11981415970843794349993507969531117573").clone().unwrap()),
      Fp::from(BigUint::from_str("20832832620288605699172743670779989646").clone().unwrap()),
      Fp::from(BigUint::from_str("60").clone().unwrap()),
      ],
      [  // a + q * 5
      Fp::from(BigUint::from_str("22884758338036014806576574749231546374").clone().unwrap()),
      Fp::from(BigUint::from_str("24999399144346326839007292404935987575").clone().unwrap()),
      Fp::from(BigUint::from_str("72").clone().unwrap()),
      ],
      [  // a + q * 6
      Fp::from(BigUint::from_str("33788100705228235263159641528931975175").clone().unwrap()),
      Fp::from(BigUint::from_str("29165965668404047978841841139091985504").clone().unwrap()),
      Fp::from(BigUint::from_str("84").clone().unwrap()),
      ]
    ];
    return LQ[index];
}

pub fn list_of_limbs_of_a_plus_kq(index: usize) -> [Fp; 3]{
    let LIST: [[Fp; 3]; 50] = [
        [
          Fp::from(BigUint::from_str("4268864003923878421072724037721852441").clone().unwrap()),
          Fp::from(BigUint::from_str("6014938634700247504123936611817064419").clone().unwrap()),
          Fp::from(BigUint::from_str("5").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("15172206371116098877655790817422281242").clone().unwrap()),
          Fp::from(BigUint::from_str("10181505158757968643958485345973062348").clone().unwrap()),
          Fp::from(BigUint::from_str("17").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("26075548738308319334238857597122710043").clone().unwrap()),
          Fp::from(BigUint::from_str("14348071682815689783793034080129060277").clone().unwrap()),
          Fp::from(BigUint::from_str("29").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("36978891105500539790821924376823138844").clone().unwrap()),
          Fp::from(BigUint::from_str("18514638206873410923627582814285058206").clone().unwrap()),
          Fp::from(BigUint::from_str("41").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("5346937607575452314483165227552541213").clone().unwrap()),
          Fp::from(BigUint::from_str("22681204730931132063462131548441056136").clone().unwrap()),
          Fp::from(BigUint::from_str("53").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("16250279974767672771066232007252970014").clone().unwrap()),
          Fp::from(BigUint::from_str("26847771254988853203296680282597054065").clone().unwrap()),
          Fp::from(BigUint::from_str("65").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("27153622341959893227649298786953398815").clone().unwrap()),
          Fp::from(BigUint::from_str("31014337779046574343131229016753051994").clone().unwrap()),
          Fp::from(BigUint::from_str("77").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("38056964709152113684232365566653827616").clone().unwrap()),
          Fp::from(BigUint::from_str("35180904303104295482965777750909049923").clone().unwrap()),
          Fp::from(BigUint::from_str("89").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("6425011211227026207893606417383229985").clone().unwrap()),
          Fp::from(BigUint::from_str("39347470827162016622800326485065047853").clone().unwrap()),
          Fp::from(BigUint::from_str("101").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("17328353578419246664476673197083658786").clone().unwrap()),
          Fp::from(BigUint::from_str("978741486102429829713049290250019350").clone().unwrap()),
          Fp::from(BigUint::from_str("114").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("28231695945611467121059739976784087587").clone().unwrap()),
          Fp::from(BigUint::from_str("5145308010160150969547598024406017279").clone().unwrap()),
          Fp::from(BigUint::from_str("126").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("39135038312803687577642806756484516388").clone().unwrap()),
          Fp::from(BigUint::from_str("9311874534217872109382146758562015208").clone().unwrap()),
          Fp::from(BigUint::from_str("138").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("7503084814878600101304047607213918757").clone().unwrap()),
          Fp::from(BigUint::from_str("13478441058275593249216695492718013138").clone().unwrap()),
          Fp::from(BigUint::from_str("150").clone().unwrap_or_default()),
        ],
        [
          Fp::from(BigUint::from_str("18406427182070820557887114386914347558").clone().unwrap()),
          Fp::from(BigUint::from_str("17645007582333314389051244226874011067").clone().unwrap()),
          Fp::from(BigUint::from_str("162").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("29309769549263041014470181166614776359").clone().unwrap()),
          Fp::from(BigUint::from_str("21811574106391035528885792961030008996").clone().unwrap()),
          Fp::from(BigUint::from_str("174").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("40213111916455261471053247946315205160").clone().unwrap()),
          Fp::from(BigUint::from_str("25978140630448756668720341695186006925").clone().unwrap()),
          Fp::from(BigUint::from_str("186").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("8581158418530173994714488797044607529").clone().unwrap()),
          Fp::from(BigUint::from_str("30144707154506477808554890429342004855").clone().unwrap()),
          Fp::from(BigUint::from_str("198").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("19484500785722394451297555576745036330").clone().unwrap()),
          Fp::from(BigUint::from_str("34311273678564198948389439163498002784").clone().unwrap()),
          Fp::from(BigUint::from_str("210").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("30387843152914614907880622356445465131").clone().unwrap()),
          Fp::from(BigUint::from_str("38477840202621920088223987897654000713").clone().unwrap()),
          Fp::from(BigUint::from_str("222").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("41291185520106835364463689136145893932").clone().unwrap()),
          Fp::from(BigUint::from_str("109110861562333295136710702838972210").clone().unwrap()),
          Fp::from(BigUint::from_str("235").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("9659232022181747888124929986875296301").clone().unwrap()),
          Fp::from(BigUint::from_str("4275677385620054434971259436994970140").clone().unwrap()),
          Fp::from(BigUint::from_str("247").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("20562574389373968344707996766575725102").clone().unwrap()),
          Fp::from(BigUint::from_str("8442243909677775574805808171150968069").clone().unwrap()),
          Fp::from(BigUint::from_str("259").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("31465916756566188801291063546276153903").clone().unwrap()),
          Fp::from(BigUint::from_str("12608810433735496714640356905306965998").clone().unwrap()),
          Fp::from(BigUint::from_str("271").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("42369259123758409257874130325976582704").clone().unwrap()),
          Fp::from(BigUint::from_str("16775376957793217854474905639462963927").clone().unwrap()),
          Fp::from(BigUint::from_str("283").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("10737305625833321781535371176705985073").clone().unwrap()),
          Fp::from(BigUint::from_str("20941943481850938994309454373618961857").clone().unwrap()),
          Fp::from(BigUint::from_str("295").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("21640647993025542238118437956406413874").clone().unwrap()),
          Fp::from(BigUint::from_str("25108510005908660134144003107774959786").clone().unwrap()),
          Fp::from(BigUint::from_str("307").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("32543990360217762694701504736106842675").clone().unwrap()),
          Fp::from(BigUint::from_str("29275076529966381273978551841930957715").clone().unwrap()),
          Fp::from(BigUint::from_str("319").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("912036862292675218362745586836245044").clone().unwrap()),
          Fp::from(BigUint::from_str("33441643054024102413813100576086955645").clone().unwrap()),
          Fp::from(BigUint::from_str("331").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("11815379229484895674945812366536673845").clone().unwrap()),
          Fp::from(BigUint::from_str("37608209578081823553647649310242953574").clone().unwrap()),
          Fp::from(BigUint::from_str("343").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("22718721596677116131528879146237102646").clone().unwrap()),
          Fp::from(BigUint::from_str("41774776102139544693482198044398951503").clone().unwrap()),
          Fp::from(BigUint::from_str("355").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("33622063963869336588111945925937531447").clone().unwrap()),
          Fp::from(BigUint::from_str("3406046761079957900394920849583923000").clone().unwrap()),
          Fp::from(BigUint::from_str("368").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("1990110465944249111773186776666933816").clone().unwrap()),
          Fp::from(BigUint::from_str("7572613285137679040229469583739920930").clone().unwrap()),
          Fp::from(BigUint::from_str("380").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("12893452833136469568356253556367362617").clone().unwrap()),
          Fp::from(BigUint::from_str("11739179809195400180064018317895918859").clone().unwrap()),
          Fp::from(BigUint::from_str("392").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("23796795200328690024939320336067791418").clone().unwrap()),
          Fp::from(BigUint::from_str("15905746333253121319898567052051916788").clone().unwrap()),
          Fp::from(BigUint::from_str("404").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("34700137567520910481522387115768220219").clone().unwrap()),
          Fp::from(BigUint::from_str("20072312857310842459733115786207914717").clone().unwrap()),
          Fp::from(BigUint::from_str("416").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("3068184069595823005183627966497622588").clone().unwrap()),
          Fp::from(BigUint::from_str("24238879381368563599567664520363912647").clone().unwrap()),
          Fp::from(BigUint::from_str("428").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("13971526436788043461766694746198051389").clone().unwrap()),
          Fp::from(BigUint::from_str("28405445905426284739402213254519910576").clone().unwrap()),
          Fp::from(BigUint::from_str("440").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("24874868803980263918349761525898480190").clone().unwrap()),
          Fp::from(BigUint::from_str("32572012429484005879236761988675908505").clone().unwrap()),
          Fp::from(BigUint::from_str("452").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("35778211171172484374932828305598908991").clone().unwrap()),
          Fp::from(BigUint::from_str("36738578953541727019071310722831906434").clone().unwrap()),
          Fp::from(BigUint::from_str("464").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("4146257673247396898594069156328311360").clone().unwrap()),
          Fp::from(BigUint::from_str("40905145477599448158905859456987904364").clone().unwrap()),
          Fp::from(BigUint::from_str("476").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("15049600040439617355177135936028740161").clone().unwrap()),
          Fp::from(BigUint::from_str("2536416136539861365818582262172875861").clone().unwrap()),
          Fp::from(BigUint::from_str("489").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("25952942407631837811760202715729168962").clone().unwrap()),
          Fp::from(BigUint::from_str("6702982660597582505653130996328873790").clone().unwrap()),
          Fp::from(BigUint::from_str("501").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("36856284774824058268343269495429597763").clone().unwrap()),
          Fp::from(BigUint::from_str("10869549184655303645487679730484871719").clone().unwrap()),
          Fp::from(BigUint::from_str("513").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("5224331276898970792004510346159000132").clone().unwrap()),
          Fp::from(BigUint::from_str("15036115708713024785322228464640869649").clone().unwrap()),
          Fp::from(BigUint::from_str("525").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("16127673644091191248587577125859428933").clone().unwrap()),
          Fp::from(BigUint::from_str("19202682232770745925156777198796867578").clone().unwrap()),
          Fp::from(BigUint::from_str("537").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("27031016011283411705170643905559857734").clone().unwrap()),
          Fp::from(BigUint::from_str("23369248756828467064991325932952865507").clone().unwrap()),
          Fp::from(BigUint::from_str("549").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("37934358378475632161753710685260286535").clone().unwrap()),
          Fp::from(BigUint::from_str("27535815280886188204825874667108863436").clone().unwrap()),
          Fp::from(BigUint::from_str("561").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("6302404880550544685414951535989688904").clone().unwrap()),
          Fp::from(BigUint::from_str("31702381804943909344660423401264861366").clone().unwrap()),
          Fp::from(BigUint::from_str("573").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("17205747247742765141998018315690117705").clone().unwrap()),
          Fp::from(BigUint::from_str("35868948329001630484494972135420859295").clone().unwrap()),
          Fp::from(BigUint::from_str("585").clone().unwrap()),
        ],
        [
          Fp::from(BigUint::from_str("28109089614934985598581085095390546506").clone().unwrap()),
          Fp::from(BigUint::from_str("40035514853059351624329520869576857224").clone().unwrap()),
          Fp::from(BigUint::from_str("597").clone().unwrap()),
        ],
      ];
      return  LIST[index];
}