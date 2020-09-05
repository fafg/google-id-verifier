package googleIDVerifier

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func getTestCerts() (*Certs, error) {
	return parseCerts(&response{Keys: []*key{
		{Kty: "RSA",
			Alg: "RS256",
			Use: "sig",
			Kid: "affc62907a446182adc1fa4e81fdba6310dce63f",
			N:   "iQM7pTQvWzrvxF9DXghTjZJ0aYq-scEwQrdhT6OHtQGP25okbLH0W-H4XiNnbBTDAyiHhStB2z_bj-2tt60P9ePxdTSMnax87-55xsEZRF66Q9Vu56JJOMRBO-ze_vd_nMIF1qo0MDZl-89wZDsGnplai1e3swvqVo3mS8E3Z6BIlh8BMQTv_BHavY6tCQ1tczlFE3DfSSEu5DnP7dPKA2c2u0ljuDRcR33nr14fpUsiVUU4q__J76-R2HvKpdMB8SQZFz5lDQzivZNQvNmHnD1VAMtFcLkQTXJ0PuNIhMw3MBMbaiOW2enoEUGRj8Q5Y-UuWRvuMocYdzxVoNiA6w",
			E:   "AQAB"},
		{Kty: "RSA",
			Alg: "RS256",
			Use: "sig",
			Kid: "3f3ef9c7803cd0b8d75247ee0d31fdd5c2cf3812",
			N:   "xM3ZHCgrJLe8y0rBZUWHOS1pCpJ2PjM_gw0WI9D0rljoZ7zWQpEC5UwpWaJqqDKxokt-kKP9GYXILqEsZrQ86qXvRZDPrP39RUjMl3Yl0hE4PlTx3aXuSE8SYqy506yduKjHw3seQHBiqSkVdLXSXqsEKUUrtFEgUxwL5L0yU4N3uJcAWK-oka8RxQSFJEilX5UOH-Qmz4UEeIr7Ma8cdsjibUc6xC9SRJtblmAdDDA_-1aMAJuYH8tGYnpTftwKbaaD0btq0LIzrsFnLu2--jaBul4u0k0jukolnUP0XSqE6NEc0iHTCdbKHZN6LrKVZoUqncTAS7Qa6TbgN1-lHw",
			E:   "AQAB"}}}, 10800)
}

func TestParseCerts(t *testing.T) {
	parsedCerts, err := getTestCerts()
	if err != nil {
		t.Error(err)
		return
	}

	expectedCerts := &Certs{
		Keys: map[string]*rsa.PublicKey{
			"3f3ef9c7803cd0b8d75247ee0d31fdd5c2cf3812": {
				N: new(big.Int),
				E: 65537,
			},
			"affc62907a446182adc1fa4e81fdba6310dce63f": {
				N: new(big.Int),
				E: 65537,
			},
		},
		Expiry: time.Now().Add(time.Second * 10800),
	}

	expectedCerts.Keys["3f3ef9c7803cd0b8d75247ee0d31fdd5c2cf3812"].N.SetString("24844215247735389310273189646274647008922907930105473431698270740526562715040581987169781839955563129267459295226881421294737169466203950884327297912301851226468638012700787347334850834131386483385438685178821398200889523325658675455447732220111464886103745777771110944034819563793625023381414618401098375084522267956455001352246857461614953881528509836974261369967100876768654380717261308721731376333077349553173361994786384889038949785777759573247989795885167886374496084199481614131554196981098869071177648787318365030522180769148649140620048471360046624502618896837283966480806507100207471935931274982036502193439", 10)
	expectedCerts.Keys["affc62907a446182adc1fa4e81fdba6310dce63f"].N.SetString("17296242026920777505872694093628503649351286117680674720541696342751499609186638812412833573842627518923036435632993139116515165638856861230982093075150242325687634067104460741817467465585243025172710929615831953088651667773608870857501096263675781190857364917839977399023617509209116870901680347085057746145917996205988882690858305796400382705959896004854628597943947825201846701841884743605665569571344356466680099138837500758926119650360617344554969483063381094098722109890837466621381925993749109727380943937515587407915846834775284429791990790529510825745951205064844824507225000813435855318957515662510163263723", 10)

	if err := equalCerts(expectedCerts, parsedCerts); err != nil {
		t.Error(err)
	}
}

func equalCerts(a, b *Certs) error {
	for id := range a.Keys {
		err := equalsRSAKeys(a.Keys, b.Keys, id)
		if err != nil {
			return err
		}
	}
	// simply check for second-granurality precision
	if a.Expiry.Unix() != b.Expiry.Unix() {
		return fmt.Errorf("expire dates mismatch: %d != %d", a.Expiry.Unix(), b.Expiry.Unix())
	}
	return nil
}

func equalsRSAKeys(a, b map[string]*rsa.PublicKey, id string) error {

	key, ok := a[id]
	if !ok {
		return errors.New("key " + id + " does not exists in a")
	}

	key2, ok := b[id]
	if !ok {
		return errors.New("key " + id + " does not exists in b")
	}

	if key.E != key2.E {
		return errors.New("RSA E mismatch")
	}

	if key.N.Cmp(key2.N) != 0 {
		return errors.New("RSA N mismatch")
	}

	return nil
}

func TestGetFederatedSignonCerts(t *testing.T) {
	certs, err := getFederatedSignOnCerts()
	if err != nil {
		t.Error(err)
		return
	}

	cachedCerts, err := getFederatedSignOnCerts()
	if err != nil {
		t.Error(err)
		return
	}

	if certs != cachedCerts {
		t.Error("expecting same instance for cached certs")
	}
}
