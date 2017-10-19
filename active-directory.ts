import * as ldap from 'ldapjs';
import { merge, is } from 'utility';
import log from 'logger';
import { LDAP as config } from 'config';

/**
 * Active Directory account types
 * 
 * See https://msdn.microsoft.com/en-us/library/ms679637%28v=vs.85%29.aspx
 */
enum AccountType {
   DomainObject = 0x0,
   GroupObject = 0x10000000,
   NonSecurityGroupObject = 0x10000001,
   AliasObject = 0x20000000,
   NonSecurityAliasObject = 0x20000001,
   UserObject = 0x30000000,
   UserAccount = 0x30000000,
   MachineAccount = 0x30000001,
   TrustAccount = 0x30000002,
   AppBasicGroup = 0x40000000,
   AppQueryGroup = 0x40000001,
   AccountMax = 0x7fffffff
};

const Field = {
   ACCOUNT_EXPIRES: 'accountExpires',
   COMMON_NAME: 'cn',
   DEPARTMENT: 'department',
   DIRECTORY_PATH: 'distinguishedName',
   LAST_FIRST: 'displayName',
   EMAIL: 'mail',
   EMPLOYEE_ID: 'employeeID',
   ENABLED: 'enabled',     // only present if account is disabled?
   FIRST_NAME: 'givenName',
   LAST_LOGON: 'lastLogon',
   LOGON_COUNT: 'logonCount',
   GROUPS: 'memberOf',
   MOBILE: 'mobile',
   NAME: 'name',
   DIRECTORY_ID: 'objectGUID',
   LOCATION: 'physicalDeliveryOfficeName',
   PASSWORD_LAST_SET: 'pwdLastSet',
   PHOTO: 'thumbnailPhoto',
   PHONE: 'telephoneNumber',
   TITLE: 'title',
   TYPE: 'objectClass',
   ACCOUNT_NAME: 'sAMAccountName'
};

const defaultFields = [
   Field.ACCOUNT_NAME,
   Field.NAME,
   Field.TITLE,
   Field.DEPARTMENT,
   Field.EMAIL,
   Field.LOCATION,
   Field.PHONE,
   Field.MOBILE
];

/**
 * Normalized directory entry
 */
interface Entry {
   [key:string]:any;
   controls?:string[];
   expired?:boolean;
   disabled?:boolean;
   contractor?:boolean;
}

interface Selection {
   /** Field attributes to include in the result */
   attributes?:string[];
   /** User types to exclude */
   exclude?:string[];
}

/**
 * Find user with account name
 */
export function findUser(accountName:string, fields:string[] = []):Promise<Entry> {
   return search({
      filter: `(${Field.ACCOUNT_NAME}=${accountName})`,
      scope: 'sub',
      sizeLimit: 400,
      attributes: fields.length > 0 ? fields : defaultFields
   });
}

/**
 * Find all users matching text
 */
export function findMatchingUsers(nameOrNumber:string, fields:string[] = defaultFields):Promise<Entry[]> {
   if (is.empty(nameOrNumber)) { return Promise.resolve([]); }

   /** Whether parts of name are long enough to search separately */
   const shouldSplit = (text:string) => {
      const min = config.minSearchLength;
      if (text.includes(' ')) {
         const parts = text.split(' ');
         return (parts[0].length >= min && parts[1].length >= min);
      } else {
         return false;
      }
   };
   let filter;

   nameOrNumber = nameOrNumber.replace(/(%20|\+)/g, ' ').trim();

   if (shouldSplit(nameOrNumber)) {
      // first and last name search
      const parts = nameOrNumber.split(' ');
      filter = `|(&(${Field.FIRST_NAME}=${parts[0]}*)(${Field.LAST_FIRST}=${parts[1]}*))` +
         `(&(${Field.FIRST_NAME}=${parts[1]}*)(${Field.LAST_FIRST}=${parts[0]}*))`;
   } else if (/\d{3}/g.test(nameOrNumber)) {
      // phone number search
      filter = `${Field.PHONE}=*${formatPhoneSearch(nameOrNumber)}*`;
   } else {
      // match either name or e-mail
      filter = `|(${Field.FIRST_NAME}=${nameOrNumber}*)(${Field.LAST_FIRST}=${nameOrNumber}*)(${Field.EMAIL}=${nameOrNumber}*)`;
   }

   return search({
      // test accounts for otherwise high security users begin with 999
      filter: `(&(${Field.TYPE}=user)(!(${config.excludeUserQuery}))(${filter}))`,
      scope: 'sub',
      sizeLimit: 400,
      attributes: fields
   });
}

/**
 * Bind to configured LDAP server and return client
 */
function connect():Promise<ldap.Client> {
   const client = ldap.createClient({ url: config.server });
   return new Promise((resolve, reject) => {
      client.bind(config.userName, config.password, err => {
         if (is.value(err)) {
            log.error(err.message);
            reject();
         } else {
            resolve(client);
         }
      });
   });
}

//function search(filter:ldap.SearchOptions):Promise<Entry[]>;
function search(filter:ldap.SearchOptions, client?:ldap.Client):Promise<Entry[]> {
   return (client === undefined)
      ? connect().then(c => search(filter, c))
      : new Promise((resolve, reject) => {
         client.search(config.userBase, filter, function(err, ad) {
            if (err) {
               log.error(err.message);
               reject();
            } else {
               const matches:Entry[] = [];
               ad.on('searchEntry', entry => {
                  const e = normalize(entry);
                  if (e !== null) { matches.push(e); }
               });
               ad.on('error', err => { reject(); });
               ad.on('end', ()=> { resolve(matches); });
            }
         });
      });
}

/**
 * The offset suggested by documentation differs from the value needed
 * to match what AD Explorer shows as the date
 * 
 * See http://meinit.nl/convert-active-directory-lastlogon-time-to-unix-readable-time
 */
function parseTimeStamp(number:number) {
   //const offset = 11676009600;    // according to documentation
   const offset = 11644473600;      // in order to make the final value match AD
   return new Date(((number / 10000000) - offset) * 1000);
}

export function login(accountName:string, password:string, fields:string[] = []):Promise<Entry> {
   //var username = req.headers['x-iisnode-auth_user']; // for example AD\username
   //var authenticationType = req.headers['x-iisnode-auth_type'];

   fields = fields.concat([
      Field.NAME,
      Field.ACCOUNT_NAME,
      Field.DIRECTORY_PATH,
      Field.ACCOUNT_EXPIRES,
      Field.ENABLED
   ]);

   return findUser(accountName, fields).then(entry => {
      const client = ldap.createClient({ url: config.server });
      // cannot bind to an expired or disabled account so retrieve fields to verify
      const expires = parseTimeStamp(entry[Field.ACCOUNT_EXPIRES]);
      const now = new Date();

      entry.expired = (expires < now);
      entry.disabled = (is.defined(entry, Field.ENABLED) && !entry[Field.ENABLED]);

      return new Promise((resolve, reject) => {
         if (entry.expired || entry.disabled) {
            // TODO: something else
            resolve(entry);
         } else {
            // verify account by using it to bind to the directory
            client.bind(entry[Field.DIRECTORY_PATH], password, err => {
               if (is.value(err)) {
                  // assume an account that cannot bind is not valid
                  reject();
               } else {
                  resolve(entry);
               }
            });
         }
      });
   });
}

/**
 * Format numbers to match AD: xxx-xxx-xxxx
 */
function formatPhoneSearch(text:string) {
   // remove all non-digits
   text = text.replace(/\D/g, '');

   // handle crazy search
   if (text.length > 10) { text = text.slice(-10); }

   if (text.length > 7) {
      // assume full xxx-xxx-xxxx search
      text = text.slice(-text.length, -7) + '-' + text.slice(-7, -4) + '-' + text.slice(-4);
   } else if (text.length > 4) {
      // assume xxx-xxxx search
      text = text.slice(-text.length, -4) + '-' + text.slice(-4);
   }
   return text;
}

/**
 * Convert binary attributes to byte arrays, clean-up names
 * and elevate attributes to top-level properties
 * 
 * See https://github.com/mcavage/node-ldapjs/issues/137
 */
function normalize(entry:ldap.Entry, exclude?:string[]):Entry|null {
   if (is.array(exclude) && exclude.findIndex(e => entry.objectName.includes(`OU=${e}`)) >= 0) {
      // entry contains an excluded OU
      return null;
   }

   const out:Entry = entry.attributes.reduce((o:Entry, a) => {
      o[a.type] = (a.type === Field.PHOTO) ? a.buffers : a.vals;
      return o;
   }, {});

   if (config.contractorOU !== null) {
      // identify contractors if their OU has been configured
      out.contractor = entry.objectclass.includes('OU=' + config.contractorOU);
   }
   if (is.array(entry.controls)) { out.controls = entry.controls.map(el => el.json); }

   return out;
}

export default {
   findUser,
   login,
   Field
};