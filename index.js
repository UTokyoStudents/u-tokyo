
const OAUTH_SECRETS = require('./client_secret.json');

const DOMAIN = 'u-tokyo.app.';
const TYPE_WHITELIST = [
    'a', 'cname', 'aaaa', 'caa', 'txt', 'mx', 'ns', 'spf', 'srv', 'sshfp',
];
const DEFAULT_TTL = 300;

const {google} = require('googleapis');

const oauth2Client = new google.auth.OAuth2(
    OAUTH_SECRETS.client_id,
    OAUTH_SECRETS.client_secret,
    'https://www.u-tokyo.app/auth'
);

const oauth2Scopes = [
    'openid',
    'email',
    'profile',
];

const express = require('express');
const app = express();
const {Element, Document} = require('void-template');

const Firestore = require('@google-cloud/firestore');

const db = new Firestore({
    projectId: 'utokyo',
});

const {DNS} = require('@google-cloud/dns');
const dns = new DNS();

const zone = dns.zone('utokyo-app');

class Subdomain
{
    constructor(id)
    {
        this._docRef = db.collection('domains').doc(id);
    }

    async getAllSubdomains()
    {
        if (this._subdomains) {
            return this._subdomains;
        }

        const doc = await this._docRef.get();
        if (!doc.exists) {
            throw new Error('No such subdomain');
        }

        return this._subdomains = doc.data().subdomains;
    }

    async getBaseSubdomains()
    {
        const subdomains = await this.getAllSubdomains();
        return subdomains.filter(subdomain => !subdomain.includes('.'));
    }

    async assertSubdomain(aSubdomain)
    {
        const subdomain = (aSubdomain || '').toLowerCase();
        const baseSubdomain = subdomain.split('.').pop();
        const subdomains = await this.getAllSubdomains();
        if (!subdomains.includes(baseSubdomain)) {
            throw new Error('Subdomain mismatch');
        }

        return subdomain;
    }

    async addSubdomain(aSubdomain)
    {
        const subdomain = await this.assertSubdomain(aSubdomain);
        const subdomains = await this.getAllSubdomains();
        if (!subdomains.includes(subdomain)) {
            await this._docRef.update({
                subdomains: Firestore.FieldValue.arrayUnion(subdomain),
            });
            delete this._subdomains;
        }
    }

    async removeSubdomain(subdomain)
    {
        subdomain = (subdomain || '').toLowerCase();
        const baseSubdomain = subdomain.split('.').pop();
        if (subdomain != baseSubdomain) {
            await this._docRef.update({
                subdomains: Firestore.FieldValue.arrayRemove(subdomain),
            });
            delete this._subdomains;
        }
    }

    validateType(aType)
    {
        const type = ((aType || '') + '').toLowerCase();
        if (!TYPE_WHITELIST.includes(type)) {
            throw new Error('Invalid type');
        }
        return type;
    }

    createRecord(aType, aName, aValue)
    {
        const value = (aValue || '') + '';
        const type = this.validateType(aType);
        const name = ((aName || '') + '').toLowerCase();

        const quarifiedName = name + '.' + DOMAIN;
        const record = zone.record(type, {
            name: quarifiedName,
            data: value.split('\n')
                .map(value => value.trim())
                .filter(value => '' != value),
            ttl: DEFAULT_TTL,
        });
        return record;
    }

    async getRecords(subdomain)
    {
        const [records] = await zone.getRecords({
            name: subdomain + '.' + DOMAIN,
        });
        return records;
    }

    async getRecordsByType(aType, aName)
    {
        const type = this.validateType(aType);
        const [records] = await zone.getRecords({
            name: aName + '.' + DOMAIN,
            type: type.toUpperCase(),
        });
        return records;
    }

    async getRecordsByTypeFormatted(aType, aName)
    {
        const results = [];
        const records = await this.getRecordsByType(aType, aName);
        for (const {name, data, type} of records) {
            const suffix = '.' + DOMAIN;
            const plainName = name.endsWith(suffix) ? name.slice(0, -suffix.length) : name;
            const record = {
                name: plainName.toLowerCase(),
                data: data.join('\n'),
                type: type.toUpperCase(),
            };
            // console.log(record);
            results.push(record);
        }
        return results;
    }

    async getAllRecords()
    {
        const subdomains = await this.getAllSubdomains();
        const results = [];

        for (const subdomain of subdomains) {
            const records = await this.getRecords(subdomain);

            for (const {name, data, type} of records) {
                const suffix = '.' + DOMAIN;
                const plainName = name.endsWith(suffix) ? name.slice(0, -suffix.length) : name
                const record = {
                    name: plainName.toLowerCase(),
                    data: data.join('\n'),
                    type: type.toUpperCase(),
                };
                // console.log(record);
                results.push(record);
            }
        }

        return results;
    }

    async updateRecord(aType, aName, aNewValue)
    {
        await this.addSubdomain(aName);
        const oldRecords = await this.getRecordsByType(aType, aName);
        //const oldRecord = this.createRecord(aType, aName, aOldValue);
        const newRecord = this.createRecord(aType, aName, aNewValue);

        await zone.createChange({
            add: newRecord,
            delete: oldRecords,
        });
    }

    async deleteRecord(aType, aName)
    {
        const subdomain = await this.assertSubdomain(aName);
        const oldRecords = await this.getRecordsByType(aType, aName);
        await zone.deleteRecords(oldRecords);
        if (subdomain.split('.').length < 2) return;
        const leftRecords = await this.getRecords(subdomain);
        if (leftRecords.length < 1) {
            this.removeSubdomain(subdomain);
        }
    }
}

app.get('/', (req, res) => {
    const document = new Document;
    const script = document.createElement ('script');
    script.setAttribute ('type', 'module');
    script.setAttribute ('src', '/main.mjs');
    document.head.append (script);
    document.title = 'Test document';

    res.send(document + '');
});

app.get('/api/v1/list-records/:domain_id', async (req, res) => {
    try {
        const obj = new Subdomain(req.params.domain_id);
        const records = await obj.getAllRecords();
        res.status(200).contentType('application/json').send(JSON.stringify({
            records,
        }));
    } catch (e) {
        console.error(e);
        res.status(400).contentType('application/json').send(JSON.stringify({
            error: e + '',
        }));
    }
});

app.post('/api/v1/update-records/:domain_id/:name/:type', async (req, res) => {
    try {
        const obj = new Subdomain(req.params.domain_id);
        await obj.updateRecord(req.params.type, req.params.name, req.query.data);
        res.status(200).contentType('application/json').send(JSON.stringify({
            success: true,
        }));
    } catch (e) {
        console.error(e);
        res.status(400).contentType('application/json').send(JSON.stringify({
            error: e + '',
        }));
    }
});

app.post('/api/v1/delete-records/:domain_id/:name/:type', async (req, res) => {
    try {
        const obj = new Subdomain(req.params.domain_id);
        await obj.deleteRecord(req.params.type, req.params.name);
        res.status(200).contentType('application/json').send(JSON.stringify({
            success: true,
        }));
    } catch (e) {
        console.error(e);
        res.status(400).contentType('application/json').send(JSON.stringify({
            error: e + '',
        }));
    }
});

app.get('/api/v1/get-records/:domain_id/:name/:type', async (req, res) => {
    try {
        const obj = new Subdomain(req.params.domain_id);
        const records = await obj.getRecordsByTypeFormatted(req.params.type, req.params.name);
        res.status(200).contentType('application/json').send(JSON.stringify({
            records,
        }));
    } catch (e) {
        console.error(e);
        res.status(400).contentType('application/json').send(JSON.stringify({
            error: e + '',
        }));
    }
});

const PORT = process.env.PORT || 8080;
const server = app.listen(PORT, () => {
    const host = server.address().address;
    const port = server.address().port;

    // console.log(`UTokyo Students Domain app listening at http://${host}:${port}`);
});
