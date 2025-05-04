import * as crypto from "crypto";
import { promisify } from "util";
import { promises as fs } from "fs";
import * as path from "path";

type EncryptedBuffer = Buffer;
type EncryptedString = string;
type SignatureBuffer = Buffer;
export type SignatureString = string;
export type RemoteSignaturePublicKeyString = String;
export type RemoteEncryptionPublicKeyString = String;
type RemoteSignaturePublicKey = crypto.KeyObject; //ED25519
type RemoteEncryptionPublicKey = Buffer; //x25519

const KEY_DIR = path.resolve(".keys");

export class CryptographicEntity {
    private localSignatureKeyPair: Promise<crypto.KeyPairKeyObjectResult>;
    private localEncryptionKeyPair: Promise<crypto.ECDH>

    constructor(keyPath?: string) {
        this.localSignatureKeyPair = this.loadOrCreateSignatureKeys(keyPath ?? KEY_DIR);
        this.localEncryptionKeyPair = this.loadOrCreateEncryptionKeys(keyPath ?? KEY_DIR);
    }

    private async loadOrCreateSignatureKeys(keyPath: string): Promise<crypto.KeyPairKeyObjectResult> {
        const privPath = path.join(keyPath, "ed25519-private.key");

        try {
            const privRaw = await fs.readFile(privPath);
            const privateKey = crypto.createPrivateKey({
                key: privRaw,
                format: 'der',
                type: 'pkcs8'
            });
            const publicKey = crypto.createPublicKey(privateKey);
            return { privateKey, publicKey };
        } catch(e: any) {
            if (e.code !== 'ENOENT') throw e;
            await fs.mkdir(keyPath, { recursive: true });
            const { publicKey, privateKey } = await promisify(crypto.generateKeyPair)('ed25519');
            const exportedPriv = privateKey.export({ format: 'der', type: 'pkcs8' });
            await fs.writeFile(privPath, exportedPriv);
            return { privateKey, publicKey };
        }
    }

    private async loadOrCreateEncryptionKeys(keyPath: string): Promise<crypto.ECDH> {
        const privPath = path.join(keyPath, "x25519-private.key");

        try {
            const privRaw = await fs.readFile(privPath);
            const ecdh = crypto.createECDH('x25519');
            ecdh.setPrivateKey(privRaw);
            return ecdh;
        } catch(e: any) {
            if (e.code !== 'ENOENT') throw e;
            await fs.mkdir(keyPath, { recursive: true });
            const ecdh = crypto.createECDH('x25519');
            ecdh.generateKeys();
            await fs.writeFile(privPath, ecdh.getPrivateKey());
            return ecdh;
        }
    }

    // Convenience methods to retrieve Base64 public keys. It's a remote key, as far as the peer is concerned.
    public async getSignaturePublicKeyB64(): Promise<RemoteSignaturePublicKeyString> {
        const { publicKey } = await this.localSignatureKeyPair;
        const pubRaw = publicKey.export({ format: 'der' } as crypto.KeyExportOptions<'der'>);
        return pubRaw.toString('base64');
    }

    public async getEncryptionPublicKeyB64(): Promise<RemoteEncryptionPublicKeyString> {
        const ecdh = await this.localEncryptionKeyPair;
        return ecdh.getPublicKey().toString('base64');
    }

    public static importRemoteSignaturePublicKey(b64: RemoteSignaturePublicKeyString): RemoteSignaturePublicKey {
        const der = Buffer.from(b64, 'base64');
        return crypto.createPublicKey({
            key: der,
            format: 'der',
            type: 'spki'
        });
    }

    public static importRemoteEncryptionPublicKey(b64: RemoteEncryptionPublicKeyString): RemoteEncryptionPublicKey {
        return Buffer.from(b64, 'base64');
    }

    async signBuffer(data: Buffer): Promise<SignatureBuffer> {
        const privateKey = (await this.localSignatureKeyPair).privateKey;
        const signature = crypto.sign(null, data, privateKey);
        return signature;
    }

    public async signString(data: string): Promise<SignatureString> {
        return this.signBuffer(Buffer.from(data, 'utf-8'))
            .then((signature) => signature.toString('base64'));
    }

    public static async verifyBuffer(
        data: Buffer, 
        signature: SignatureBuffer, 
        remotePublicKey: RemoteSignaturePublicKey, 
        failureMode: "void" | "throw" = "throw")
    : Promise<Buffer | void> {
        const isValid = crypto.verify(null, data, remotePublicKey, signature);
        if (!isValid) {
            if (failureMode === "throw") {
                throw new Error("Signature verification failed");
            }
            return;
        }
        return data;
    }
    public async verifyString(
        data: string, 
        signature: SignatureString, 
        publicKey: RemoteSignaturePublicKey, failureMode: "void" | "throw" = "throw")
    : Promise<String | void> {
        return CryptographicEntity.verifyBuffer(
                Buffer.from(data, 'utf-8'), 
                Buffer.from(signature, 'base64'), 
                publicKey, 
                failureMode)
            .then((data) => data?.toString('utf-8'));
    }
    public async encryptBuffer(data: Buffer, remotePublicKey: RemoteEncryptionPublicKey): Promise<EncryptedBuffer> {
        const localECDH = await this.localEncryptionKeyPair;
    
        // Generate shared secret
        const sharedSecret = localECDH.computeSecret(remotePublicKey);
    
        // Derive symmetric key
        const key = crypto.createHash('sha256').update(sharedSecret).digest();
    
        // AES-GCM encryption
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const tag = cipher.getAuthTag();
    
        // Return: iv + tag + ciphertext (for ECDH)
        return Buffer.concat([iv, tag, encrypted]);
    }
    public async encryptString(data: string, remotePublicKeyB64: RemoteEncryptionPublicKeyString): Promise<EncryptedString> {
        return this.encryptBuffer(Buffer.from(data, 'utf-8'), CryptographicEntity.importRemoteEncryptionPublicKey(remotePublicKeyB64))
            .then((encrypted) => encrypted.toString('base64'));
    }
    public async decryptBuffer(
        data: EncryptedBuffer,
        publicKey: RemoteEncryptionPublicKey,
        failureMode: "void" | "throw" = "throw"
    ): Promise<Buffer | void> {
        const localECDH = await this.localEncryptionKeyPair;
    
        // Compute shared secret from remote public key
        const sharedSecret = localECDH.computeSecret(publicKey); // publicKey is raw Buffer
        const key = crypto.createHash('sha256').update(sharedSecret).digest();
    
        try {
            // Extract iv (12 bytes), tag (16 bytes), and ciphertext
            const iv = data.subarray(0, 12);
            const tag = data.subarray(12, 28);
            const ciphertext = data.subarray(28);
    
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
            decipher.setAuthTag(tag);
    
            const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
            return decrypted;
        } catch (err) {
            if (failureMode === "throw") {
                throw new Error("Decryption failed or data is tampered.");
            }
            return;
        }
    }

    public async decryptString(data: EncryptedString, publicKey: RemoteEncryptionPublicKey, failureMode: "void" | "throw" = "throw"): Promise<String | void> {
        return this.decryptBuffer(Buffer.from(data, 'base64'), publicKey, failureMode)
            .then((decrypted) => decrypted?.toString('utf-8'))
    }

} 