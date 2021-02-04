use crate::commitment::{new_smt, pow2, FieldElement, FieldElementsSMT, FieldHash, Error};
use primitives::{Coord, FieldBasedHash};
use algebra::Field;

fn hash_pair(first: &FieldElement, second: &FieldElement) -> FieldElement {
    hash_vec(&vec![first, second])
}

fn hash_vec(data: &Vec<&FieldElement>) -> FieldElement {
    let mut hasher = <FieldHash>::init(None);
    for &fe in data {
        hasher.update(*fe);
    }
    hasher.finalize()
}

// Tunable parameters
const FWT_SMT_HEIGHT:  usize = 12;
const BWTR_SMT_HEIGHT: usize = 12;
const CERT_SMT_HEIGHT: usize = 12;
const SCC_SMT_HEIGHT:  usize = 12;

const FWT_SMT_CAPACITY:  usize = pow2(FWT_SMT_HEIGHT);
const BWTR_SMT_CAPACITY: usize = pow2(BWTR_SMT_HEIGHT);
const CERT_SMT_CAPACITY: usize = pow2(CERT_SMT_HEIGHT);
const SCC_SMT_CAPACITY:  usize = pow2(SCC_SMT_HEIGHT);

const FWT_PATH_SUFFIX:  &str = "_fwt";
const BWTR_PATH_SUFFIX: &str = "_bwtr";
const CERT_PATH_SUFFIX: &str = "_cert";
const SCC_PATH_SUFFIX:  &str = "_scc";

// Types of contained subtrees
pub enum SidechainSubtreeType {
    FWT, BWTR, CERT, SCC, CSW
}

pub struct SidechainTree{
    sc_id:    FieldElement,     // ID of a sidechain, for which SidechainTree is created
    csw:      FieldElement,     // CSW

    fwt_smt:  FieldElementsSMT, // SMT for Forward Transfer Transactions
    bwtr_smt: FieldElementsSMT, // SMT for Backward Transfers Requests Transactions
    cert_smt: FieldElementsSMT, // SMT for Certificates
    scc_smt:  FieldElementsSMT, // SMT for Sidechain Creation Transactions

    fwt_num:  usize,            // Number of contained Forward Transfers Transactions
    bwtr_num: usize,            // Number of contained Backward Transfers Requests Transactions
    cert_num: usize,            // Number of contained Certificates
    scc_num:  usize             // Number of contained Sidechain Creation Transactions
}

impl SidechainTree{

    // Creates a new instance of SidechainTree with a specified ID
    pub fn create(sc_id: &FieldElement, db_path: &str) -> Result<SidechainTree, Error> {
        if !db_path.is_empty(){
            // Name of a directory shouldn't be too big, so length of sc_id string is reduced to 40-characters via Sha-1 hash to preserve uniqueness of the sc_id
            let sc_id_suffix = sha1::Sha1::from(sc_id.to_string()).digest().to_string();
            let sc_base_path = db_path.to_owned() + sc_id_suffix.as_str();

            Ok(
                SidechainTree{
                    sc_id:    (*sc_id).clone(),
                    csw:      FieldElement::zero(),

                    fwt_smt:  new_smt(&(sc_base_path.to_owned() + FWT_PATH_SUFFIX),  FWT_SMT_HEIGHT)?,
                    bwtr_smt: new_smt(&(sc_base_path.to_owned() + BWTR_PATH_SUFFIX), BWTR_SMT_HEIGHT)?,
                    cert_smt: new_smt(&(sc_base_path.to_owned() + CERT_PATH_SUFFIX), CERT_SMT_HEIGHT)?,
                    scc_smt:  new_smt(&(sc_base_path.to_owned() + SCC_PATH_SUFFIX),  SCC_SMT_HEIGHT)?,

                    fwt_num:  0,
                    bwtr_num: 0,
                    cert_num: 0,
                    scc_num:  0
                }
            )
        } else {
            Err("Empty db_path".into())
        }
    }

    // Gets ID of a SidechainTree
    pub fn id(&self) -> &FieldElement { &self.sc_id }

    // Inserts leaf into SMT by a specified position which is incremented afterwards
    // Returns false if there is no more place to insert a leaf
    fn add_leaf(tree: &mut FieldElementsSMT, leaf: &FieldElement, pos: &mut usize, capacity: usize) -> bool {
        if *pos < capacity {
            tree.insert_leaf(Coord::new(0, *pos), *leaf); *pos += 1;
            true
        } else {
            false
        }
    }

    // Sequentially adds leafs to the FWT SMT
    pub fn add_fwt(&mut self, fwt: &FieldElement) -> bool {
        SidechainTree::add_leaf(&mut self.fwt_smt, fwt, &mut self.fwt_num, FWT_SMT_CAPACITY)
    }

    // Sequentially adds leafs to the BWTR SMT
    pub fn add_bwtr(&mut self, bwtr: &FieldElement) -> bool {
        SidechainTree::add_leaf(&mut self.bwtr_smt, bwtr, &mut self.bwtr_num, BWTR_SMT_CAPACITY)
    }

    // Sequentially adds leafs to the CERT SMT
    pub fn add_cert(&mut self, cert: &FieldElement) -> bool {
        SidechainTree::add_leaf(&mut self.cert_smt, cert, &mut self.cert_num, CERT_SMT_CAPACITY)
    }

    // Sequentially adds leafs to the SCC SMT
    pub fn add_scc(&mut self, scc: &FieldElement) -> bool {
        SidechainTree::add_leaf(&mut self.scc_smt, scc, &mut self.scc_num, SCC_SMT_CAPACITY)
    }

    // Sets CSW value
    pub fn set_csw(&mut self, csw: &FieldElement){ self.csw = *csw }

    // Gets commitment of the Forward Transfer Transactions tree
    pub fn get_fwt_commitment(&self)  -> FieldElement { self.fwt_smt.get_root() }

    // Gets commitment of the Backward Transfer Requests Transactions tree
    pub fn get_bwtr_commitment(&self) -> FieldElement { self.bwtr_smt.get_root() }

    // Gets commitment of the Certificates tree
    pub fn get_cert_commitment(&self) -> FieldElement { self.cert_smt.get_root() }

    // Gets commitment of the Sidechain Creation Transactions tree
    pub fn get_scc_commitment(&self)  -> FieldElement { self.scc_smt.get_root() }

    // Gets commitment of a SidechainTree
    // Commitment = hash( [hash(fwt_root) | hash(bwtr_root)] | [hash(cert_root) | hash(scc_root)] | CSW | SC_ID )
    pub fn get_commitment(&self) -> FieldElement {
        let fwt_bwtr_hash = hash_pair(
            &self.get_fwt_commitment(),
            &self.get_bwtr_commitment()
        );
        let cert_scc_hash = hash_pair(
            &self.get_cert_commitment(),
            &self.get_scc_commitment()
        );
        hash_vec(&vec![&fwt_bwtr_hash, &cert_scc_hash, &self.csw, &self.sc_id])
    }
}

#[test]
fn sample_sidechain_tree(){
    let sc_id = FieldElement::one();

    // Empty db_path is not allowed
    assert!(SidechainTree::create(&sc_id, "").is_err());

    let mut sct = SidechainTree::create(&sc_id, "./sct_").unwrap();

    // Initial commitment values of empty subtrees before updating them
    let empty_fwt  = sct.get_fwt_commitment ();
    let empty_bwtr = sct.get_bwtr_commitment();
    let empty_cert = sct.get_cert_commitment();
    let empty_scc  = sct.get_scc_commitment ();
    // Initial commitment value of an empty SCT
    let empty_comm = sct.get_commitment();

    // All subtrees have the same initial commitment value
    assert_eq!(empty_fwt, empty_bwtr);
    assert_eq!(empty_scc, empty_cert);
    assert_eq!(empty_fwt, empty_scc);

    let fe = FieldElement::one();
    // Updating subtrees
    sct.add_fwt (&fe);
    sct.add_bwtr(&fe);
    sct.add_cert(&fe);
    sct.add_scc (&fe);

    // All updated subtrees should have non-empty commitment values
    assert_ne!(empty_fwt,  sct.get_fwt_commitment ());
    assert_ne!(empty_bwtr, sct.get_bwtr_commitment());
    assert_ne!(empty_cert, sct.get_cert_commitment());
    assert_ne!(empty_scc,  sct.get_scc_commitment ());

    // Updating CSW
    sct.set_csw(&fe);
    // Check that CSW is correctly updated
    assert!(sct.csw == fe);

    // SCT commitment has non-empty value
    assert_ne!(empty_comm, sct.get_commitment());
}
