use crate::commitment::decode_eip1184_rlp_proof;
use crate::errors::Error;
use alloc::vec::Vec;
use alloy_primitives::hex;
use ethereum_consensus::types::{Address, H256};
use ethereum_light_client_verifier::execution::ExecutionVerifier;
use optimism_ibc_proto::ibc::lightclients::optimism::v1::AccountUpdate as ProtoAccountUpdate;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountUpdateInfo {
    pub account_proof: Vec<Vec<u8>>,
    pub account_storage_root: H256,
}

impl TryFrom<ProtoAccountUpdate> for AccountUpdateInfo {
    type Error = Error;
    fn try_from(value: ProtoAccountUpdate) -> Result<Self, Self::Error> {
        Ok(Self {
            account_proof: decode_eip1184_rlp_proof(value.account_proof)?,
            account_storage_root: H256::from_slice(&value.account_storage_root),
        })
    }
}

impl AccountUpdateInfo {
    pub fn verify_account_storage(
        &self,
        ibc_address: &Address,
        state_root: H256,
    ) -> Result<(), Error> {
        let execution_verifier = &ExecutionVerifier;
        match execution_verifier
            .verify_account(state_root, ibc_address, self.account_proof.clone())
            .map_err(|e| {
                Error::MPTVerificationError(
                    e,
                    state_root,
                    hex::encode(ibc_address.0),
                    self.account_proof.iter().map(hex::encode).collect(),
                )
            })? {
            Some(account) => {
                if self.account_storage_root == account.storage_root {
                    Ok(())
                } else {
                    Err(Error::AccountStorageRootMismatch(
                        self.account_storage_root,
                        account.storage_root,
                        state_root,
                        hex::encode(ibc_address.0),
                        self.account_proof.iter().map(hex::encode).collect(),
                    ))
                }
            }
            None => {
                if self.account_storage_root.is_zero() {
                    Ok(())
                } else {
                    Err(Error::AccountStorageRootMismatch(
                        self.account_storage_root,
                        H256::default(),
                        state_root,
                        hex::encode(ibc_address.0),
                        self.account_proof.iter().map(hex::encode).collect(),
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::account::AccountUpdateInfo;
    use alloc::vec;
    use alloy_primitives::hex;
    use ethereum_consensus::types::{Address, H256};
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::AccountUpdate as ProtoAccountUpdate;

    #[test]
    fn test_verify_account_storage() {
        let proto_account_update = ProtoAccountUpdate {
            account_proof: hex!("f901fff90191a05844e303fa8db3fa31c729db25d9b593367f853b4cbcb1a91fc85eda11e16617a09bb111cd80eee4c6ae6af0d01422ae82fccfa80d0267c4c8d525bc7f2b6233afa0323230228b1ba9b7eb88084b6d1ed9b75813a2da2d5ff0df9067335f5f55444ca0bfca1461a76f96944aa00afff03dc8de770275fbbe360f6ee03b0fe0ce902fd8a04c7579812e09de2b1aa746b0a047d357e898e9d634ac185d7e9d25b3d2336ab3808080a0c7de43d788c5228ebde29b62cb0f9b9eb10c0cb9b1078d6a51f768e0cdf296d6a0b8ad2523a3d1fdf33b627f598622775508297710e3623de115f2174c7f5727dfa023910890abfb016861bb7916cb555add80e552f118c0f1b93ec7d26798976f1da077153f3a45bebfb8b6709bd52e71d0993e9ecfd4e425204e258e5e5ac775ee73a01b42efb18b5af3defc59ba21f68965c5a28c716e109df937d216a2041fee4770a06b4b8f8ad0ae7588581c191bf177d5020fcc0f9152123cd26b3acf4e3469744280a0b4ec201ec80c64cefbe351f2febea48eb21c0d65d3e1c868178ece65e3d63ff480f869a0346090ccaa6fa9fa12360268a84aaba21af051a53bfdc84493350c840f61b79eb846f8440180a0d70e9391a3dd508a60195d2a5e12fb2f7e49582f9ce2c12477299377ccfadaada073092abb9be4a3fa206fd43699af07ff9d4278c27693f013fceb7780f3654c09").to_vec(),
            account_storage_root: hex!("d70e9391a3dd508a60195d2a5e12fb2f7e49582f9ce2c12477299377ccfadaad").to_vec()
        };
        let account_update = AccountUpdateInfo::try_from(proto_account_update).unwrap();
        let res = account_update.verify_account_storage(
            &Address(hex!("ff77D90D6aA12db33d3Ba50A34fB25401f6e4c4F")),
            H256(hex!(
                "48b7747ba1094684d9197bbaa5dcb134587d23e493fb53a29e400c50e50f5147"
            )),
        );
        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    fn test_verify_account_storage_non_existence() {
        let proto_account_update = ProtoAccountUpdate {
            account_proof: hex!("f90c8bf90211a0735c089329da81ce7b2d42666be5a1937cba65e1e018ca007d2d89097643093da050ac94d9d3f41b5affc198a6fe058bbf0b5c325da0bc89914e94cd792c835ec7a0dd6fafef2a8250c254db15fa44c2d53dc543eddb86800bcd892bd98c0adb2fafa0603d4baa1bf91623b90e4d7760123036058fabdc5895f1efab03d9bc9b92da9ea0688c8a3f57cf3579a8b19011d9a811e5bcbcd467216935fdfde60884e6af7991a0812a0308609cc2b529630ab727abd3b1aa974896e4cd0a02bbe517f77b142a2ba02904a77c6e9c680d4d302e5a51b847fca63a6532b21b07dd41a3ac49f4151349a0e179454a28109b5aab7b880693b5786b568781d9aa45986f74be7d6a7a818d72a07f3363c3908198f0aaa22c64185be10461a51524bc2b53f5d622caef25c672a0a0e65b893234155029bcf2f893bfdf4498509062c0949eb0ffc027c075267b999fa01d6a1e0b72b63a7a00083a40572d4041116a286fa3a2d747b25fa0cefe07642ca0d8b29fe0f182ddf0482f5b3ab6b3a0640e63177a78eadf75f5773ed534214e4aa0de1d7bd5c5dbc04a2f734621a7225856c722cce92fe201cab1348282b05a1d97a0f9e111c8222ff2bc2fe565ff7f626c9748239c2038e288380081eb2a3af0c908a07dd132ff024cf49ed3f49149f8bae764e9a173f499ccfcd9f408dd2000bb531da0b954951fd86e5b275c759fbd29eaa292f3c84fdbb6bcc5b1e714a1d838582aae80f90211a04d152a07d2c9c1547501953755563814d7cb184a7756551eaf482b759dae5769a07316575d385637101fdb5f52e676e10f25ae0aa08eee125a7e5bedf4aad6c122a011e2f69401bab09a648aff06e1893c93e2e58a9635d0bcbeb56ae3f585a04b85a086e49bb50598013f14675177ae79c1da54e6c2bbaf91c3b1341142c29271c409a0ceff5f5bd8e1824b24651f15e4ba56fee26cb0b9173f7d4ebab3e0293c7269e7a0fecedf695e9918f9c3397accb5416c4696999fa64fa2e842ec79be8cb93a8651a0854ca3709cc3460ada39aea9619d7f571c117b6054ecb2c4370584d63cf03641a0826eff5d12e4895656e42b47bb3ae6d82027b210c09c85ea702c117193beab3da009fe1cc705eb0d3ac788027f618c076ef1510aadcee6cd736ac931c763f9ef67a0cafc24169ce2d0bc3a14471e1d74470cf692df45e672a4b5281be6634d0f06f4a06dd0a6ae12c583185056c34a27b4df3e66b7da685d90b05e05f73e4904dd502aa0a43f00480c0a7219aca6e9681573abe0206a0ac744fddbd721a00d9342bbc418a0f97f13efdb911e697b75663c41dca7e5b31ad93a6d460bac224e30c1188fb7e3a07fc2f215ae82e3c19b48ec6f1a28427f17a04668308f573c20b68626bc85955ca04896f54096f0489f5d0649b4d7fc796caccfbb275dfa1a90b8b9be2116a7e273a0cdbca11f9ed5ea1d347dd6f40c8bdb8505f21deb53161ea57ebd08fe0becfa8f80f90211a03bf4c6b5933c499c155a6edb44b781dc408992c2c4c16ca1d75ad19e23fafeefa0b55c56b13f5d19dde3d7d96cc156a92d2feb78d29125f9bd2925202f466313a7a0244e4254c915f0209716c58e02b1e59702b3b9a28c5c59d361dd06cd91ec70f9a06ea7d219827e2a71031d36d892fffb6aca878ec90f0e1086cbf6a5dd1ff8763ba0751e39cd8c27f3607a42d11897cd190d0984be5847cbe6100751d06d04c637bba002871c10a84f539119d02559afcc35d6751864529189ce5c7038a2c118601fe3a0306ff9c515871b0080b9334022351644dbe44901c2b2f267311675829c1307fca0a963d8f5da27142226b9607bd09d1aa7d64f3615236bc22cb7439045b0d93abea0e91fb125186252297f099d76d4f40ee948d5a0fb2b469ee63c685db204be7a4ca0ccd4667345dd458431de1d9fab425f36553d444e9b059d847d72b4a193971f1aa0d3b2c96703267e6040450109d4226f4b05cd4274c5f4ed99aa97b83b70044bf1a0543e2abdea1838ca8408ac52fb1d7fb170b2e822aa6989558d4fbf47a0f8b851a016b137139bdb068d710119ec01df37f40e6c6db0c31346bf083893a73e3402e0a070ef51e27ac486580d225c4f7bb73f6456f2fbc69ea5e945471d9c86268d3da4a0838f376bf27fbe43dcede5396b787b4047ab9ab13c3d54b71ea7ded3aeb44ef1a02c207350ede911a939db2cbde3644c5508592fe281d97b7f798753779ae6651a80f90211a04081815e12cf03a52f183def5e687076094b0bc6387363c051b3e4b1be4d1d19a06c73c48b7349672f346b03a3df4838129ed5f92eddddd7e2d1e2efad591602cba0b78231ff87a3f6b239661cde00ea1f605e78a70886467d2fba5ec455327182a4a00e844f2238c3a9a7401aacd5382fd8e9ade8c5d9a2ed18936f18b7a4a0ce0159a0f0cf87ad75cbe0d422d501ceecd3eeb2322e987dd06b948719296214d2b1bd3da0b972c5937a9fc152bc6fa930e84060e2bef4a63d83978a4ec6bc14b60bf452efa0db85e78720006b5ea6e7b258522837815cfb16a3c634e74913394239fb83397ea0f79388ee57552bb0f2cd6fb7fcb716156607be0f95acdab409b64f590c7d7f72a0140623eb8411a98ac14271b6838908e6a27803bfea3073aef8c8825eaed50fe1a09400f4a94faf9a7a80d58f889ca08a665c82e1cac2039a7fcc0ae9698621f1e0a0ebb02920f9288829afb95192e7466da33e45f996d9cd29d7fc06cad275663d47a0dfd361a59760d8542085eb26b3108ccda0111407637599dfd6ee1db3f8d7829ea07bfd10a32a6183ace7f87df01d5dc24bf0e9d09f65e7954096ab6386ac72bf3fa056a0b81e9ddedb42072c3b9100cf911c1933d16e231dde74647d33b7e8de95b7a0ed1a49b7ed1daea815c0cb7400776af17dbc4b27300cffc5c5d61ce01305f6c6a0b98bf6e4aadc8c9f754d04107972e868325c1c0b65338b14e80a8754952c533780f90211a06c58a57085037dfc8db7fcc57396521078f8fcfb9e76eeb2b45d3408c1fdd191a056dcc694badf8487675150d3f90d7452e1d008da178140a84cab3708e94eb4eda06ee4844656a92e04a04a5469280c9d69b4f12ab8f29896b2645fcb92603bea80a0807c0b0f7cdfa86c4390d62202ad4eacfe0a6182189b34bad027db16336c5a78a02b1b7221d0a98161170a5008a702030f8ec84d02f939b59755952ce3437bba0aa01c5e574e042f54cf46caec858db5ca34901a000195d1f044e03dcbb66f904e36a0d0f3ab90005c9f49578bbba90bca526e4034d86d49fde2c8269be58a30f540e3a0145539ee81a9fb21e1af7b5851d57a497765dd5c4351904c8a725ec755e0ce52a0e90a6fd2863da09c2bf1f1a4f0d8f04a095bdc76816000aeaef5bb20e4f717d9a033d95a81d8b601f9dbdbea947a7052eb849dd91875e734da645c9f240418c72fa053dc0376d2c1309c1bbe7755d7ede7bfa4af13c2c933538a539c75bdecbd9e53a0707665486d4924ae7eecfcf41f7f804906140baecf43fa72ec8419bcdfd48f1ba0ccf9006732611705137f5562d6b59442af44c13ea97df11c09df468dbe0a7323a0385c7d72bf637b580a2ddec76007d12d1048a2553ec662d96ed25ccedd97053fa0939aa354a3598e3248baf25e27953c3812b2c555d5e43db59d330ab6f9e8c3c3a0c941eff5b200af34d12362bf73856fa0164d788274804245239e66c55091135080f901b18080a0a3c8aca2eeb300dc458c7fc99aadba23e3bbd0f88e9def4c89c8c58c5e4b468aa02440a82db7c8b7044dd2fba70e5204e481032a630173d8d9752851e7df7e4240a0a60accaa78c07a21cfb1414797e9d8dd1236cf96bb1bb56235ac899906c25bc7a047e97e35f2cd979e6b93001f40002e22a0e754923d6e093c0f7cf2578d460e82a017e89cef18477aa7708df31998c60d1acd734e0266e70d8388914ab6f53d7ce9a000031279827d634f41754800f88bc0e9e134cb2d1d66065493c6ef32f22ed1c6a03bdc555af1c06c2c53d99b142ef0fc72c4b58bbfe63975c1aeda24a3eb2ea66ca06408ef004b300be9baccefd12ee648e24adc85841af0d0037c56c3992a0a5e2d80a0b4c8ba93a4166cfc2a051400b8afcdb41d5c74be9d105fb39613f8d9ab064a4da073f59f57bc2e6297832cb37f6618ba99279e2f32d2661110c1682ed2e8694c7ca056ec3e008e136bdf75ee10371aad81c93e6592dc5224b0b3018fea73bae89f7da01cf891d6aa49256fbe12d75e60adfbc612826164564eb89c19371a2625fb8633a04b147c2c876e2578176a1789f8c80d2c4674fbc6ea1cdd319e4b89085594fc4880f87180808080a0898c7859ae8ec9411296d9568545abbe3395dcab69264d16de52cf2489bea53e808080808080a0fdbf45b5370653412069c67c697029941cc4c34a563d265b2b34f95656cb2a38a06a47e9ff626afe400b0591b2632976db76ff66355e000d89b39fa40c3148934f80808080").to_vec(),
            account_storage_root: vec![0u8;32]
        };
        let account_update = AccountUpdateInfo::try_from(proto_account_update).unwrap();
        let res = account_update.verify_account_storage(
            &Address(hex!("a7f733a4fEA1071f58114b203F57444969b86524")),
            H256(hex!(
                "568a51c3253bbd2d46e3923b35df0489712df11453fd04dd71341120356952c0"
            )),
        );
        assert!(res.is_ok(), "{:?}", res);
    }
}
