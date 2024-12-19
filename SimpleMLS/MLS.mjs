import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

/**
 * Utility to generate a key pair using the HPKE CipherSuite.
 */
async function generateKeyPair() {
  const suite = new CipherSuite({
    kem: KemId.DhkemX25519HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Chacha20Poly1305,
  });
  const keyPair = await suite.kem.generateKeyPair();
  return keyPair;
}

/**
 * Serialize a key to ArrayBuffer.
 */
async function exportKey(key) {
  return key; // HPKE keys are already in the correct format
}

/**
 * MLS Library for Secure Messaging
 */


class MLS {
  constructor() {
    this.groups = {}; // Store groups with their secrets, members, and message history
  }

  async createGroup(groupId, members) {
    const groupSecret = await this.generateGroupSecret();
    this.groups[groupId] = {
      secret: groupSecret,
      epoch: 0,
      members,
      messageHistory: [],
    };
    console.log(`Group '${groupId}' created with members: ${members}`);
  }

  async addMember(groupId, newMember) {
    const group = this.groups[groupId];
    if (!group) throw new Error(`Group '${groupId}' does not exist.`);

    group.members.push(newMember);
    await this.updateEpoch(groupId);
    console.log(`Member '${newMember}' added to group '${groupId}'.`);
  }

  async removeMember(groupId, removedUser) {
    const group = this.groups[groupId];
    if (!group) throw new Error(`Group '${groupId}' does not exist.`);

    group.members = group.members.filter((member) => member !== removedUser);
    if (group.members.length === 0) {
      throw new Error(`Cannot remove the last member of the group.`);
    }

    await this.updateEpoch(groupId);
    console.log(`Member '${removedUser}' removed from group '${groupId}'.`);
  }

  async sendMessage(groupId, sender, message) {
    const group = this.groups[groupId];
    if (!group) throw new Error(`Group '${groupId}' does not exist.`);

    const suite = new CipherSuite({
      kem: KemId.DhkemX25519HkdfSha256,
      kdf: KdfId.HkdfSha256,
      aead: AeadId.Chacha20Poly1305,
    });

    const senderContext = await suite.createSenderContext({
      recipientPublicKey: group.secret.publicKey,
    });

    const ciphertext = await senderContext.seal(
      new TextEncoder().encode(message)
    );

    // Store both ciphertext and encapsulation key (enc) in message history
    group.messageHistory.push({
      sender,
      ciphertext,
      enc: senderContext.enc, // Include the encapsulation key
    });

    console.log(`Message sent by '${sender}' in group '${groupId}'.`);
    return { ciphertext, enc: senderContext.enc }; // Return enc with ciphertext
  }

  async receiveMessage(groupId, recipient, ciphertext, enc) {
    const group = this.groups[groupId];
    if (!group) throw new Error(`Group '${groupId}' does not exist.`);

    const suite = new CipherSuite({
      kem: KemId.DhkemX25519HkdfSha256,
      kdf: KdfId.HkdfSha256,
      aead: AeadId.Chacha20Poly1305,
    });

    if (!enc) throw new Error(`Encapsulation key is missing.`);

    const recipientContext = await suite.createRecipientContext({
      recipientKey: group.secret.privateKey,
      enc, // Use the encapsulation key from the sender
    });

    const plaintext = await recipientContext.open(ciphertext);

    console.log(
      `Message received by '${recipient}' in group '${groupId}': ${new TextDecoder().decode(
        plaintext
      )}`
    );
    return new TextDecoder().decode(plaintext);
  }

  async updateEpoch(groupId) {
    const group = this.groups[groupId];
    if (!group) throw new Error(`Group '${groupId}' does not exist.`);

    group.epoch += 1;
    group.secret = await this.generateGroupSecret();
    console.log(`Group '${groupId}' updated to epoch ${group.epoch}.`);
  }

  async generateGroupSecret() {
    const keyPair = await generateKeyPair();
    return {
      publicKey: await exportKey(keyPair.publicKey),
      privateKey: await exportKey(keyPair.privateKey),
    };
  }

  //ratchet tree functions
  /* The level of a node in the tree. Leaves are level 0, their parents
  are level 1, etc. If a node's children are at different levels,
  then its level is the max level of its children plus one. */
  function level(node){
    k = 0;
    if(x & 0x01){return k;}
    while((node >> k)&0x01){
      k++;
    }
    return k;
  }

  //The number of nodes needed to represent a tree with n leaves.
  function nodeWidth(n){
    if(n===0){return 0;}
    else{return 2*(n - 1) + 1;}
  }

  //The index of the root node of a tree with n leaves.
  function root(n){
    var w = nodeWidth(n);
    return (1 << Math.log2(w)) - 1);
  }

  //The left child of an intermediate node.
  function left(node){
    var k = level(node);
    if(k === 0){throw('leaf node has no children');}

    return node ^ (0x01 << (k - 1));
  }

  //The right child of an intermediate node.
  function right(node){
    var k = level(node)
    if k == 0{throw('leaf node has no children');}

    return x ^ (0x03 << (k - 1));
  }

  //The parent of a node.
  function parent(node, n){
    if (node === root(n)){throw('root node has no parent');}

    var = level(node);
    var b = (node >> (k + 1)) & 0x01;
    return (node | (1 << k)) ^ (b << (k + 1));
  }

  //The other child of the node's parent.
  function sibling(node, n){
    var p = parent(node, n);
    if (node < p){return right(p);}
    else{return left(p);}
  }

  //The direct path of a node, ordered from leaf to root.
  function direct_path(node, n){
    var r = root(n);
    if (node == r){return [];}  //return a blank path (root of node is itself)

    var d = [];
    var pnode;
    while node_in != r:
        pnode = parent(node, n);
        d.push(pnode); //append parent node
    return d;
  }

  //The copath of a node, ordered from leaf to root.
  function copath(node, n):
    if node == root(n){return [];} //return blank path (root of node is itself)

    var d = direct_path(node, n);
    d.unshift(node);
    d.pop();

    //python version: return [sibling(y, n) for y in d]
    var s = [];
    for(var = 0; i<d.length; i++){
      s.push(sibling(d[i]));
    }
    return s;
  }

  //The common ancestor of two nodes is the lowest node that is in the
  //direct paths of both leaves.
  function common_ancestor_semantic(nodex, nodey, n){
    //intersection of arrays in js
    var tempx = new Set([nodex]);
    var tempPathx = new Set(direct_path(nodex, n))
    var dx = tempx.union(tempPathx);
    var tempy = new Set([nodey]);
    var tempPathy = new Set(direct_path(nodey, n));
    var dy = tempy.union(tempPathy));
    var dxy = dx.intersection(dy);
    if (dxy.size === 0){throw('failed to find common ancestor');}

    var ldxy = [];
    for(var val of dxy){
      ldxy.push(level(val));
    }
    return Math.min(ldxy); //min(dxy, key=level)
  }

  //The common ancestor of two nodes is the lowest node that is in the
  //direct paths of both leaves.
  function common_ancestor_direct(nodex, nodey, _){
    //Handle cases where one is an ancestor of the other
    var lx = level(nodex)+1;
    var ly = level(nodey)+1;
    if ((lx <= ly) && (nodex>>ly === nodey>>ly)){return nodey;}
    else if ((ly <= lx) && (x>>lx == y>>lx)){return x;}

    //Handle other cases
    var xn = nodex
    var yn = nodey
    var k = 0;
    while (xn !== yn):
       xn = xn >> 1;
       yn = yn >> 1;
       k++;
    return (xn << k) + (1 << (k-1)) - 1;
  }

}

export default MLS;
