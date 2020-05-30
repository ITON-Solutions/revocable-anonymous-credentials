/*
 *
 *  The MIT License
 *
 *  Copyright 2019 ITON Solutions.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

package org.iton.jssi.ursa.anoncred.util;

import org.iton.jssi.ursa.anoncred.CredentialPrimaryPrivateKey;
import org.iton.jssi.ursa.anoncred.issuer.IssuerEmulator;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;

import static org.iton.jssi.ursa.anoncred.util.BigNumber.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

class BigNumberTest {

    private static final int RANGE_LEFT = 592;
    private static final int RANGE_RIGHT = 592;

    @Test
    void primeInRange() {
        SecureRandom random = new SecureRandom();
        BigInteger start = new BigInteger(RANGE_LEFT, random);
        BigInteger end = new BigInteger(RANGE_RIGHT, random);
        int compare = start.compareTo(end);

        if (compare > 0) {
            BigInteger temp = start;
            start = end;
            end = temp;
        }

        BigInteger result = BigNumber.primeInRange(start, end);
        assertTrue(result.isProbablePrime(100));
        assertTrue(start.compareTo(result) < 0);
        assertTrue(end.compareTo(result) >= 0);
    }

    @Test
    void lagrange() {
        Map<String, BigInteger> result = BigNumber.lagrange(1506099439);
        assertEquals(result.get("0").intValue(), 38807);
        assertEquals(result.get("1").intValue(), 337);
        assertEquals(result.get("2").intValue(), 50);
        assertEquals(result.get("3").intValue(), 11);
    }

    @Test
    void encodeAttribute() throws NoSuchAlgorithmException {
        BigInteger encoded = BigNumber.encodeAttribute("5435", BigNumber.ByteOrder.BIG);
        assertEquals(encoded.toString(10), "83761840706354868391674207739241454863743470852830526299004654280720761327142");
    }

    @Test
    void modPow() {
        BigInteger base = new BigInteger("12714671911903680502393098440562958150461307840092575886187217264492970515611166458444182780904860535776274190597528985988632488194981204988199325501696648896748368401254829974173258613724800116424602180755019588176641580062215499750550535543002990347313784260314641340394494547935943176226649412526659864646068220114536172189443925908781755710141006387091748541976715633668919725277837668568166444731358541327097786024076841158424402136565558677098853060675674958695935207345864359540948421232816012865873346545455513695413921957708811080877422273777355768568166638843699798663264533662595755767287970642902713301649", 10);
        BigInteger exp = new BigInteger("13991423645225256679625502829143442357836305738777175327623021076136862973228390317258480888217725740262243618881809894688804251512223982403225288178492105393953431042196371492402144120299046493467608097411259757604892535967240041988260332063962457178993277482991886508015739613530825229685281072180891075265116698114782553748364913010741387964956740720544998915158970813171997488129859542399633104746793770216517872705889857552727967921847493285577238", 10);
        BigInteger modulus = new BigInteger("991272771610724400277702356109350334773782112020672787325464582894874455338156617087078683660308327009158085342465983713825070967004447592080649030930737560915527173820649490032274245863850782844569456999473516497618489127293328524608584652323593452247534656999363158875176879817952982494174728640545484193154314433925648566686738628413929222467005197087738850212963801663981588243042912430590088435419451359859770426041670326127890520192033283832465411962274045956439947646966560440910244870464709982605844468449227905039953511431640780483761563845223213570597106855699997837768334871601402132694515676785338799407204529154456178837013845488372635042715003769626150545960460800980936426723680755798495767188398126674428244764038147226578038085253616108968402209263400729503458144370189359160926796812468410806201905992347006546335038212090539118675048292666041345556742530041533878341459110515497642054583635133581316796089099043782055893003258788369004899742992039315008110063759802733045648131896557338576682560236591353394201381103042167106112201578883917022695113857967398885475101031596068885337186646296664517159150904935112836318654117577507707562065113238913343761942585545093919444150946120523831367132144754209388110483749", 10);
        BigInteger n = base.modPow(exp, modulus);
        assertTrue(n.equals(new BigInteger("156669382818249607878298589043381544147555658222157929549484054385620519150887267126359684884641035264854247223281407349108771361611707714806192334779156374961296686821846487267487447347213829476609283133961216115764596907219173912888367998704856300105745961091899745329082513615681466199188236178266479183520370119131067362815102553237342546358580424556049196548520326206809677290296313839918774603549816182657993044271509706055893922152644469350618465711055733369291523796837304622919600074130968607301641438272377350795631212741686475924538423333008944556761300787668873766797549942827958501053262330421256183088509761636226277739400954175538503984519144969688787730088704522060486181427528150632576628856946041322195818246199503927686629821338146828603690778689292695518745939007886131151503766930229761608131819298276772877945842806872426029069949874062579870088710097070526608376602732627661781899595747063793310401032556802468649888104062151213860356554306295111191704764944574687548637446778783560586599000631975868701382113259027374431129732911012887214749014288413818636520182416636289308770657630129067046301651835893708731812616847614495049523221056260334965662875649480493232265453415256612460815802528012166114764216881", 10)));

        base = BigInteger.valueOf(6);
        exp = BigInteger.valueOf(5).negate();
        modulus = BigInteger.valueOf(13);
        assertEquals(BigInteger.valueOf(7), base.modPow(exp, modulus));


        modulus = BigInteger.ONE;
        assertEquals(BigInteger.ZERO, base.modPow(exp, modulus));

        modulus = BigInteger.ZERO;
        assertThrows(ArithmeticException.class, () -> {
            BigInteger.valueOf(6).modPow(BigInteger.valueOf(5).negate(), BigInteger.ZERO);
        });

        modulus = BigInteger.ONE.negate();
        assertEquals(BigInteger.ZERO, BigNumber.modPow(base, exp, modulus));

        modulus = BigInteger.valueOf(5).negate();
        assertEquals(BigInteger.ONE, BigNumber.modPow(base, exp, modulus));
    }

    @Test
    void inverse() {
        BigInteger bn = BigInteger.valueOf(3);
        assertEquals(BigInteger.valueOf(16), bn.modInverse(BigInteger.valueOf(47)));

        bn = BigInteger.valueOf(9);
        assertEquals(BigInteger.valueOf(3), bn.modInverse(BigInteger.valueOf(13)));

        SecureRandom random = new SecureRandom();

        BigInteger modulus = BigInteger.probablePrime(128, random);

        for (int i = 0; i < 25; i++) {
            byte[] bytes = new byte[16];
            random.nextBytes(bytes);
            BigInteger r = new BigInteger(bytes);
            BigInteger s = r.modInverse(modulus);
            // mod_mul
            BigInteger res = r.multiply(s).mod(modulus);
            assertEquals(res, BigInteger.ONE);
        }

        modulus = BigInteger.probablePrime(128, random).multiply(modulus);

        for (int i = 0; i < 25; i++) {
            byte[] bytes = new byte[32];
            random.nextBytes(bytes);
            BigInteger r = new BigInteger(bytes);
            BigInteger s = r.modInverse(modulus);
            // mod_mul
            BigInteger res = r.multiply(s).mod(modulus);
            assertEquals(res, BigInteger.ONE);
        }
    }

    @Test
    void safePrime() {

        int iterations = 10;
        long start = System.currentTimeMillis();
        for (int i = 0; i < iterations; i++) {
            BigInteger p = BigNumber.safePrime(LARGE_PRIME, new SecureRandom());
            boolean result = p.subtract(BigInteger.ONE).shiftRight(1).isProbablePrime(100);
            assertTrue(result);
        }
        System.out.println("Average time = " + (System.currentTimeMillis() - start) / iterations / 1000 + " sec");
    }

    @Test
    void isSafePrime() {
        // safe prime: q is prime and 2*q + 1 is prime
        BigInteger q = new BigInteger("18088387217903330459", 10);
        assertTrue(q.isProbablePrime(CERTAINTY));
        assertTrue(BigNumber.isSafePrime(q));

        q = new BigInteger("33376463607021642560387296949", 10);
        assertTrue(q.isProbablePrime(CERTAINTY));
        assertTrue(BigNumber.isSafePrime(q));

        q = new BigInteger("170141183460469231731687303717167733089", 10);
        assertTrue(q.isProbablePrime(CERTAINTY));
        assertTrue(BigNumber.isSafePrime(q));

        q = new BigInteger("113910913923300788319699387848674650656041243163866388656000063249848353322899", 10);
        assertTrue(q.isProbablePrime(CERTAINTY));
        assertTrue(BigNumber.isSafePrime(q));

        q = new BigInteger("1675975991242824637446753124775730765934920727574049172215445180465220503759193372100234287270862928461253982273310756356719235351493321243304213304923049", 10);
        assertTrue(q.isProbablePrime(CERTAINTY));
        assertTrue(BigNumber.isSafePrime(q));

        q = new BigInteger("153739637779647327330155094463476939112913405723627932550795546376536722298275674187199768137486929460478138431076223176750734095693166283451594721829574797878338183845296809008576378039501400850628591798770214582527154641716248943964626446190042367043984306973709604255015629102866732543697075866901827761489", 10);
        assertTrue(q.isProbablePrime(CERTAINTY));
        assertTrue(BigNumber.isSafePrime(q));

        q = new BigInteger("66295144163396665403376179086308918015255210762161712943347745256800426733181435998953954369657699924569095498869393378860769817738689910466139513014839505675023358799693196331874626976637176000078613744447569887988972970496824235261568439949705345174465781244618912962800788579976795988724553365066910412859", 10);
        assertTrue(q.isProbablePrime(CERTAINTY));
        assertTrue(BigNumber.isSafePrime(q));

        q = new BigInteger("820487282547358769999412885360222660576380474310550379805815205126382064582513754977028835433175916179747652683836060304824653681337501863788890799590780972441917586297563543467703579662178567005653571376063099400019232223632330329795684409261771589617763237736441493626109590280374575246142877096898790823019919184975618595550451798334727636308466158736200343427240101972133364701056380402654685095871114841124384154429149515486150114363963276777169261541633795383304623350867534398592252716751849685025134858878838140569141018718631392957748884293332928915134136215143014948055229407749052752101848315855158944468016884298587263993258236848884932980148243876982276799403077114631798358541555605636220846630743269407933148520394657959774584499003246457264189421332913812855364345248054990102801114399784993674416044569272611209733832017619177693894139979496122025481552572188051013282143916147122297298055829333928425354847295988683286038218946776211988871738419664461787066106418386242958463113678229760398832001107060788455379133616893701874144525350368407189299943856497368730891887657349819575057553523442357336804219224754445704270452590146111445528895773014533306318524971435831504890959063653868338360441906137639730716820611", 10);
        assertTrue(q.isProbablePrime(CERTAINTY));
        assertTrue(BigNumber.isSafePrime(q));

        // p = 2*q + 1 => q = (p - 1)/2
        BigInteger p = new BigInteger("298425477551432359319017298068281828134535746771300905126443720735756534287270383542467183175737460443806952398210045827718115111810885752229119677470711305345901926067944629292942471551423868488963517954094239606951758940767987427212463600313901180668176172283994206392965011112962119159458674722785709556623", 10);
        assertTrue(p.isProbablePrime(CERTAINTY));
        q = p.subtract(BigInteger.ONE).shiftRight(1);
        assertTrue(BigNumber.isSafePrime(q));
    }

    @Test
    void genX() {
        int iterations = 100;
        IssuerEmulator emulator = new IssuerEmulator();
        CredentialPrimaryPrivateKey credentialPrimaryPrivateKey = emulator.getCredentialPrimaryPrivateKey();
        for (int i = 0; i < iterations; i++) {
            BigInteger gen = BigNumber.genX(credentialPrimaryPrivateKey.p, credentialPrimaryPrivateKey.q);
            assertTrue(gen.compareTo(BigInteger.valueOf(2)) >= 0);
            assertTrue(gen.compareTo(credentialPrimaryPrivateKey.p.multiply(credentialPrimaryPrivateKey.q).subtract(BigInteger.ONE)) < 0);
        }
    }

    @Test
    void randomInRange(){
        BigInteger safe_prime = new BigInteger("298425477551432359319017298068281828134535746771300905126443720735756534287270383542467183175737460443806952398210045827718115111810885752229119677470711305345901926067944629292942471551423868488963517954094239606951758940767987427212463600313901180668176172283994206392965011112962119159458674722785709556623", 10);
        int iterations = 100;
        for (int i = 0; i < iterations; i++) {
            BigInteger random = BigNumber.randomInRange(BigInteger.ZERO, safe_prime, new SecureRandom());
            assertTrue(random.compareTo(safe_prime) < 0, String.format("Iteration %d", i));
        }
    }

    @Test
    void random(){

        for(int i = 0; i < 100; i++) {
            BigInteger result = BigNumber.random(LARGE_MASTER_SECRET);
            assertEquals(LARGE_MASTER_SECRET, result.bitLength());

            result = BigNumber.random(LARGE_VPRIME);
            assertEquals(LARGE_VPRIME, result.bitLength());

            result = BigNumber.random(LARGE_PRIME);
            assertEquals(LARGE_PRIME, result.bitLength());
        }
    }

    @Test
    public void pow() {
        BigInteger test = BigInteger.valueOf(3).pow(2);
        assertEquals(BigInteger.valueOf(9), test);
        BigInteger answer = new BigInteger("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929677132122730441323862712594345230336", 10);
        assertEquals(answer, LARGE_E_START_VALUE);
    }
}
