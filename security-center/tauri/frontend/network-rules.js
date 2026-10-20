/* Network rule presentation. All normalization, authorization and writes stay
   behind the existing typed Security Context boundary. */
(() => {
  const en = {
    title: "Network rules", intro: "Choose what applications can reach and which incoming connections this computer accepts.",
    applications: "Applications", incoming: "Incoming access", new: "New rule", search: "Search rules", refresh: "Refresh",
    empty: "No rules here yet", emptyCopy: "Create a rule, or start from a connection in Network Activity.",
    unavailable: "Rule service unavailable", unavailableCopy: "Your existing security services continue independently. No rule has been assumed active.",
    name: "Rule name", executable: "Executable path", executableHint: "Matches this executable, including code and extensions it runs. Individual Flatpak and script identities are not yet supported.",
    action: "Action", allow: "Allow", deny: "Block", lifetime: "Duration", permanent: "Permanent", boot: "Until reboot", "15m": "15 minutes", "1h": "One hour",
    destinations: "Destinations", destinationHint: "Leave empty for any destination. Separate entries with commas: example.org, *.example.org, 203.0.113.4, 2001:db8::/32.",
    advanced: "Advanced options", protocols: "Protocol", both: "TCP and UDP", anyProtocol: "Any IP protocol", ports: "Ports", portsHint: "Empty means any port. For example: 443, 8000-8010.",
    family: "Address family", any: "IPv4 and IPv6", scope: "Applies to", user: "My account", system: "All users", zone: "Firewall zone", service: "Service", customPorts: "Custom ports", source: "Source address or subnet", sourceHint: "Empty means any source in the selected zone.",
    description: "Note", review: "Review changes", apply: "Authenticate and apply", cancel: "Cancel", edit: "Edit", duplicate: "Duplicate", disable: "Disable", enable: "Enable", remove: "Delete", up: "Move earlier", down: "Move later",
    reviewTitle: "Review network changes", reviewCopy: "These changes are not applied yet. Authentication confirms this exact transaction.",
    saving: "Waiting for protected authentication…", saved: "Policy saved for future matching connections. Existing connections may remain open.",
    previewError: "The change could not be reviewed.", applyError: "The change was not applied.", loading: "Reading current rules…", import: "Import", export: "Export", importHint: "Import adds reviewed rules; it does not replace your existing policy.",
    exportTitle: "Export network rules", exportCopy: "This export contains all rules for the selected provider and their network scopes. Review it before sharing.",
    selected: "Selected rules", enabled: "Enabled", disabled: "Disabled", all: "All states", next: "Next", previous: "Previous", total: "rules", owner: "GREYWARD", currentPage: "Export this page", close: "Close",
    savedState: "Saved", loadedState: "Loaded by engine", observedState: "Observed matching", expiredState: "Expired", disabledState: "Disabled", unavailableState: "Unavailable",
    nativeScope: "Executable scope", wholeSystem: "System-wide incoming access", allowNotice: "Allow does not block other destinations. Managed DNS and threat restrictions still apply.",
    revokeNotice: "Deleting or disabling a rule changes future decisions; it does not recover data or necessarily close established connections.",
    noEdit: "An active administrator session is required to change rules.", sameEngine: "OpenSnitch controls application connections. firewalld controls incoming access.",
    summary: "Rule summary", importError: "Choose a valid GREYWARD network-rule export of at most 1 MiB.", pending: "Saved is not the same as observed enforcement.",
    external: "Existing firewalld configuration", readOnly: "Managed elsewhere · read only", runtime: "Runtime", permanentPlane: "Permanent configuration", limited: "This provider disclosure is limited to 128 entries.", serviceDefined: "Service-defined ports and protocols", active: "Active rules", matches: "Observed decisions", lastUsed: "Last observed", undo: "Undo last change", anyDestination: "Any destination", anySource: "Any source", exportAll: "Export rules",
  };
  const fr = {
    title: "Règles réseau", intro: "Choisissez les destinations accessibles aux applications et les connexions entrantes acceptées par cet ordinateur.",
    applications: "Applications", incoming: "Accès entrant", new: "Nouvelle règle", search: "Rechercher des règles", refresh: "Actualiser",
    empty: "Aucune règle pour le moment", emptyCopy: "Créez une règle ou partez d’une connexion dans l’activité réseau.",
    unavailable: "Service de règles indisponible", unavailableCopy: "Les services de sécurité continuent indépendamment. Aucune règle n’est supposée active.",
    name: "Nom de la règle", executable: "Chemin de l’exécutable", executableHint: "Cible cet exécutable, y compris le code et les extensions qu’il lance. Les identités Flatpak et de scripts individuelles ne sont pas encore prises en charge.",
    action: "Action", allow: "Autoriser", deny: "Bloquer", lifetime: "Durée", permanent: "Permanente", boot: "Jusqu’au redémarrage", "15m": "15 minutes", "1h": "Une heure",
    destinations: "Destinations", destinationHint: "Vide : toute destination. Séparez par des virgules : example.org, *.example.org, 203.0.113.4, 2001:db8::/32.",
    advanced: "Options avancées", protocols: "Protocole", both: "TCP et UDP", anyProtocol: "Tout protocole IP", ports: "Ports", portsHint: "Vide : tout port. Exemple : 443, 8000-8010.",
    family: "Famille d’adresses", any: "IPv4 et IPv6", scope: "S’applique à", user: "Mon compte", system: "Tous les utilisateurs", zone: "Zone du pare-feu", service: "Service", customPorts: "Ports personnalisés", source: "Adresse ou sous-réseau source", sourceHint: "Vide : toute source dans la zone sélectionnée.",
    description: "Note", review: "Examiner les changements", apply: "S’authentifier et appliquer", cancel: "Annuler", edit: "Modifier", duplicate: "Dupliquer", disable: "Désactiver", enable: "Activer", remove: "Supprimer", up: "Placer avant", down: "Placer après",
    reviewTitle: "Examiner les changements réseau", reviewCopy: "Rien n’est encore appliqué. L’authentification confirme cette transaction précise.",
    saving: "En attente de l’authentification protégée…", saved: "Politique enregistrée pour les prochaines connexions correspondantes. Les connexions existantes peuvent rester ouvertes.",
    previewError: "Impossible d’examiner le changement.", applyError: "Le changement n’a pas été appliqué.", loading: "Lecture des règles actuelles…", import: "Importer", export: "Exporter", importHint: "L’import ajoute des règles après examen ; il ne remplace pas votre politique.",
    exportTitle: "Exporter les règles réseau", exportCopy: "Cet export contient toutes les règles du fournisseur sélectionné et leur portée réseau. Examinez-le avant de le partager.",
    selected: "Règles sélectionnées", enabled: "Activée", disabled: "Désactivée", all: "Tous les états", next: "Suivante", previous: "Précédente", total: "règles", owner: "GREYWARD", currentPage: "Exporter cette page", close: "Fermer",
    savedState: "Enregistrée", loadedState: "Chargée par le moteur", observedState: "Correspondance observée", expiredState: "Expirée", disabledState: "Désactivée", unavailableState: "Indisponible",
    nativeScope: "Portée de l’exécutable", wholeSystem: "Accès entrant pour le système", allowNotice: "Autoriser ne bloque pas les autres destinations. Les restrictions DNS et contre les menaces restent applicables.",
    revokeNotice: "Supprimer ou désactiver une règle modifie les décisions futures ; cela ne récupère pas les données et ne ferme pas nécessairement les connexions existantes.",
    noEdit: "Une session administrateur active est nécessaire pour modifier les règles.", sameEngine: "OpenSnitch contrôle les connexions des applications. firewalld contrôle l’accès entrant.",
    summary: "Résumé de la règle", importError: "Choisissez un export GREYWARD valide de 1 Mio maximum.", pending: "Enregistrée ne signifie pas que l’application effective a été observée.",
    external: "Configuration firewalld existante", readOnly: "Gestion externe · lecture seule", runtime: "Active à l’exécution", permanentPlane: "Configuration permanente", limited: "Cette vue du fournisseur est limitée à 128 entrées.", serviceDefined: "Ports et protocoles du service", active: "Règles actives", matches: "Décisions observées", lastUsed: "Dernière observation", undo: "Annuler le dernier changement", anyDestination: "Toute destination", anySource: "Toute source", exportAll: "Exporter les règles",
  };
  const catalogs = Object.fromEntries(Object.entries({en, fr}).map(([locale, catalog]) => [locale,
    Object.fromEntries(Object.entries(catalog).map(([key, value]) => [`network.rules.${key}`, value]))]));
  function destinations(value) {
    return String(value || "").split(/[,\n]/).map(v => v.trim()).filter(Boolean).map(value => ({
      kind: value.startsWith("*.") ? "domain" : value.includes("/") ? "network" : value.includes(":") || /^\d+(\.\d+){3}$/.test(value) ? "ip" : "host",
      value: value.startsWith("*.") ? value.slice(2) : value,
    }));
  }
  function portsText(value) { if (typeof value === "string") return value; return (value || []).map(([a, b]) => a === b ? String(a) : `${a}-${b}`).join(", "); }
  function destinationText(value) { return (value || []).map(d => (d.kind === "domain" ? "*." : "") + d.value).join(", "); }
  const workflowCopy = {
    en: {allFlows:"All rules",direction:"Traffic",outgoing:"Application connections",inbound:"Incoming connections",order:"Order",rule:"Rule",from:"Source",to:"Destination",services:"Services & ports",decision:"Action",state:"Status",trafficType:"Traffic direction",flowHint:"Define the flow, choose its service, then review the exact changes.",localApplication:"Application on this computer",remoteSource:"Remote source",thisDevice:"This computer",anyApplication:"Any application",anyService:"Any TCP/UDP port",chooseService:"Search a service or port…",customService:"Custom ports",customHint:"Enter ports or ranges, for example 443, 8000-8010.",installedServices:"Installed services",additionalConditions:"Includes additional service conditions",outboundUnsupported:"This definition cannot be represented safely as one application rule. Use explicit ports and protocol instead.",serviceUnavailable:"Service definitions are incomplete. Unknown ports are not assumed.",noServiceMatch:"No service matches this search",serviceSelection:"Service selection",clearService:"Use custom ports",serviceDefinition:"Incoming rules follow firewalld’s service definition, including its additional conditions. Application rules use the exact displayed ports.",engine:"Enforcement",flowOrder:"Each direction has its own evaluation order. Rows from different engines do not form one shared chain.",reviewFor:"Review changes for",providerUnavailable:"This direction is unavailable",searchAll:"Search rule, application, address, service or port",noResults:"No matching rules",noResultsCopy:"Change the search or traffic filter to see your rules.",applyScope:"Only the reviewed direction is changed by this transaction.",newFlow:"New network rule",editFlow:"Edit network rule",create:"Create",update:"Update",delete:"Delete",availabilityChange:"Change availability",restoreOrder:"Restore rule order",move:"Change order",restore:"Restore",definitionMissing:"Definition unavailable",catalogSource:"Service names and port definitions come from the installed firewalld catalog.",exportApplications:"Export application rules",exportIncoming:"Export incoming rules",unavailableDirections:"Some directions could not be read. Their rules are not assumed absent.",draftScope:"Choose the traffic direction to reveal its supported conditions.",portsProtocols:"Ports / protocol"},
    fr: {allFlows:"Toutes les règles",direction:"Trafic",outgoing:"Connexions des applications",inbound:"Connexions entrantes",order:"Ordre",rule:"Règle",from:"Source",to:"Destination",services:"Services et ports",decision:"Action",state:"État",trafficType:"Sens du trafic",flowHint:"Définissez le flux, choisissez son service, puis vérifiez les changements exacts.",localApplication:"Application sur cet ordinateur",remoteSource:"Source distante",thisDevice:"Cet ordinateur",anyApplication:"Toute application",anyService:"Tout port TCP/UDP",chooseService:"Rechercher un service ou un port…",customService:"Ports personnalisés",customHint:"Saisissez des ports ou plages, par exemple 443, 8000-8010.",installedServices:"Services installés",additionalConditions:"Comprend des conditions de service supplémentaires",outboundUnsupported:"Cette définition ne peut pas être représentée sûrement par une seule règle d’application. Choisissez des ports et un protocole explicites.",serviceUnavailable:"Certaines définitions de service sont indisponibles. Aucun port inconnu n’est supposé.",noServiceMatch:"Aucun service ne correspond",serviceSelection:"Sélection du service",clearService:"Utiliser des ports personnalisés",serviceDefinition:"Les règles entrantes suivent la définition firewalld, y compris ses conditions supplémentaires. Les règles d’application utilisent les ports exacts affichés.",engine:"Moteur",flowOrder:"Chaque sens possède son propre ordre d’évaluation. Les lignes des deux moteurs ne forment pas une chaîne commune.",reviewFor:"Vérifier les changements pour",providerUnavailable:"Ce sens est indisponible",searchAll:"Rechercher une règle, application, adresse, un service ou port",noResults:"Aucune règle correspondante",noResultsCopy:"Modifiez la recherche ou le filtre de trafic pour retrouver vos règles.",applyScope:"Seul le sens vérifié est modifié par cette transaction.",newFlow:"Nouvelle règle réseau",editFlow:"Modifier la règle réseau",create:"Créer",update:"Modifier",delete:"Supprimer",availabilityChange:"Changer la disponibilité",restoreOrder:"Restaurer l’ordre des règles",move:"Changer l’ordre",restore:"Restaurer",definitionMissing:"Définition indisponible",catalogSource:"Les noms des services et leurs ports proviennent du catalogue firewalld installé.",exportApplications:"Exporter les règles d’application",exportIncoming:"Exporter les règles entrantes",unavailableDirections:"Certains sens n’ont pas pu être lus. Leurs règles ne sont pas considérées absentes.",draftScope:"Choisissez le sens du trafic pour afficher les conditions prises en charge.",portsProtocols:"Ports / protocole"},
  };
  for (const [locale, values] of Object.entries(workflowCopy)) Object.assign(catalogs[locale], Object.fromEntries(Object.entries(values).map(([k,v]) => [`network.rules.${k}`,v])));

  function serviceScope(service) {
    if (!service?.simple || !Array.isArray(service.ports) || !service.ports.length || service.ports.length > 64) return null;
    const groups = {};
    for (const [port, protocol] of service.ports) {
      if (!["tcp","udp"].includes(protocol) || !/^\d+(?:-\d+)?$/.test(port)) return null;
      const [start,end = start] = String(port).split("-").map(Number);
      if (start < 1 || end > 65535 || end < start) return null;
      (groups[protocol] ||= []).push([start,end]);
    }
    const normalized = Object.values(groups).map(ranges => {
      const result = [];
      for (const [a,b] of ranges.sort((x,y)=>x[0]-y[0] || x[1]-y[1])) {
        if (result.length && a <= result.at(-1)[1]+1) result.at(-1)[1] = Math.max(b,result.at(-1)[1]);
        else result.push([a,b]);
      }
      return result;
    });
    if (normalized.some(ports => JSON.stringify(ports) !== JSON.stringify(normalized[0]))) return null;
    return {ports:normalized[0],protocols:Object.keys(groups).sort()};
  }
  const servicePortLabel = service => (service?.ports || []).map(([p,protocol]) => `${p}/${String(protocol).toUpperCase()}`).join(" · ");

  const separateCopy = {
    en:{applicationRules:"Application rules",ipFiltering:"IP filtering",applicationIntro:"Choose an installed application, then define its allowed or blocked connections.",ipIntro:"Manage this computer’s incoming and outgoing IP rules with explicit source, destination, services and action.",chooseApplication:"Choose an application",searchApplications:"Search installed applications…",installedApplications:"Installed applications",nativeApplication:"Native application",flatpakUnsupported:"Individual Flatpak scope is not supported by this engine.",launcherUnsupported:"This launcher cannot be mapped safely to one executable.",catalogUnavailable:"The installed application list is unavailable.",catalogLimited:"Some applications could not be listed. Refresh to try again.",noApplicationMatch:"No matching application",applicationScope:"The rule follows the selected executable, including its extensions. Other helper executables are separate.",selectedApplication:"Selected application",incomingDirection:"Incoming",outgoingDirection:"Outgoing",allDirections:"All directions",ipOnly:"Enter IP addresses or CIDR subnets, separated by commas.",ipRequired:"IP filtering accepts IP addresses and CIDR subnets; use application rules for hostname conditions.",enabled:"Enabled",disabled:"Disabled",configuration:"Configuration",details:"Technical scope",nativeScope:"Executable scope",localFirewall:"Local computer firewall",outgoingOrder:"Outgoing IP and application rules share OpenSnitch’s order. The shown position is its actual global position. Incoming rules use firewalld’s separate order.",noForwarding:"These rules protect this computer; NAT, routing and transit filtering are not configured here.",changeApplication:"Change application",ipRule:"IP rule",applicationCatalogNote:"Names and icons describe installed launchers. Authorization still reviews the exact executable and account scope."},
    fr:{applicationRules:"Règles applications",ipFiltering:"Filtrage IP",applicationIntro:"Choisissez une application installée, puis définissez ses connexions autorisées ou bloquées.",ipIntro:"Gérez les règles IP entrantes et sortantes de cet ordinateur : source, destination, services et action.",chooseApplication:"Choisir une application",searchApplications:"Rechercher une application installée…",installedApplications:"Applications installées",nativeApplication:"Application native",flatpakUnsupported:"Le moteur ne prend pas en charge une règle propre à ce Flatpak.",launcherUnsupported:"Ce lanceur ne peut pas être relié sûrement à un seul exécutable.",catalogUnavailable:"La liste des applications installées est indisponible.",catalogLimited:"Certaines applications n’ont pas pu être listées. Actualisez pour réessayer.",noApplicationMatch:"Aucune application correspondante",applicationScope:"La règle suit l’exécutable choisi, extensions comprises. Les autres exécutables auxiliaires restent distincts.",selectedApplication:"Application sélectionnée",incomingDirection:"Entrant",outgoingDirection:"Sortant",allDirections:"Tous les sens",ipOnly:"Adresses IP ou sous-réseaux CIDR, séparés par des virgules.",ipRequired:"Le filtrage IP accepte des adresses IP et sous-réseaux CIDR ; utilisez les règles applications pour les noms d’hôte.",enabled:"Activée",disabled:"Désactivée",configuration:"Configuration",details:"Périmètre technique",nativeScope:"Exécutable concerné",localFirewall:"Pare-feu de cet ordinateur",outgoingOrder:"Les règles IP sortantes et applications partagent l’ordre OpenSnitch. La position affichée est sa position globale réelle. Les règles entrantes suivent l’ordre distinct de firewalld.",noForwarding:"Ces règles protègent cet ordinateur ; elles ne configurent ni NAT, ni routage, ni filtrage du trafic en transit.",changeApplication:"Changer d’application",ipRule:"Règle IP",applicationCatalogNote:"Noms et icônes décrivent les lanceurs installés. L’autorisation porte toujours sur l’exécutable exact et le compte concernés."}
  };
  for(const language of Object.keys(separateCopy))Object.assign(catalogs[language],Object.fromEntries(Object.entries(separateCopy[language]).map(([k,v])=>[`network.rules.${k}`,v])));
  function create({request, esc, icon, identity, t}) {
    const state = {provider:"application",view:"applications",filterProvider:"all",applicationQuery:"",applicationOpen:false,data:null,draft:null,editing:null,preview:null,busy:false,error:"",feedback:"",search:"",filter:"",offset:0,selected:new Set(),exportText:"",undo:null,serviceOpen:false,serviceQuery:"",serviceIndex:0};
    let root = null, loadSequence = 0, previewSequence = 0, restoringFocus = false;
    const c = key => t(`network.rules.${key}`);
    const providerName = provider => c(provider === "incoming" ? "inbound" : "outgoing");
    const engine = provider => provider === "incoming" ? "firewalld" : "OpenSnitch";
    const serviceDetails = () => state.data?.catalog?.service_details || [];
    const canEdit = provider => state.data?.providers?.[provider]?.capabilities?.edit === true;
    const call = async (method,payload,timeout=15000) => {
      const result = await request(`network_rules_${method}`,{payload},timeout);
      if (result?.ok !== true) throw new Error(result?.detail || c("unavailable"));
      return result;
    };
    async function readProvider(provider) {
      const rows = []; let offset = 0, first;
      do {
        const page = await call("list",{provider,offset});
        first ||= page;
        if (!Array.isArray(page.rules) || page.revision !== first.revision || rows.length+page.rules.length > 1024 || page.rules.some(r=>r.provider !== provider)) throw new Error(c("previewError"));
        rows.push(...page.rules);
        if (page.next_offset != null && (!Number.isInteger(page.next_offset) || page.next_offset <= offset || page.next_offset > 1024)) throw new Error(c("previewError"));
        offset = page.next_offset;
      } while (offset != null);
      return {...first,rules:rows,next_offset:null,total:rows.length};
    }
    async function load() {
      const sequence = ++loadSequence;
      for (let attempt=0;attempt<2;attempt++) {
        const values = await Promise.allSettled([readProvider("application"),readProvider("incoming")]);
        if (sequence !== loadSequence) return state.data;
        const providers = Object.fromEntries(values.map((v,i)=>[["application","incoming"][i],v.status === "fulfilled" ? v.value : {rules:[],capabilities:{edit:false},detail:v.reason?.message || c("unavailable")} ]));
        const available = Object.values(providers).filter(p=>Number.isInteger(p.revision));
        if (new Set(available.map(p=>p.revision)).size > 1) { if (!attempt) continue; state.error=c("previewError");state.data=null;return null; }
        const rows = Object.values(providers).flatMap(p=>p.rules);
        if (rows.length > 1024 || !available.length || new Set(rows.map(r=>r.id)).size !== rows.length) {state.error=c("unavailable");state.data=null;return null;}
        state.data = {ok:true,revision:available[0].revision,actor_uid:available[0].actor_uid,rules:rows,total:rows.length,providers,
          catalog:providers.incoming.catalog || {},external:providers.incoming.external,
          applications:providers.application.applications || [],installedApplications:providers.application.installed_applications || {items:[],unavailable:true},capabilities:{edit:Object.values(providers).some(p=>p.capabilities?.edit)}};
        state.offset=Math.min(state.offset,Math.max(0,Math.floor((filteredRules().length-1)/100)*100));
        state.error = values.some(v=>v.status === "rejected") ? c("unavailableDirections") : Object.entries(providers).filter(([,p])=>p.detail).map(([provider,p])=>`${providerName(provider)}: ${p.detail}`).join(" · ");
        return state.data;
      }
    }
    function fresh(values={}) {
      previewSequence++;state.provider=values.provider || state.provider;
      state.draft={provider:state.provider,name:"",path:"",action:"deny",scope:"user",lifetime:"permanent",enabled:true,protocols:["tcp","udp"],ports:[],family:"any",destinations:[],zone:state.data?.catalog?.zones?.includes("public") ? "public" : state.data?.catalog?.zones?.[0] || "",service:"",source:"",description:"",...values};
      if(state.view==="ip"){if(!Object.hasOwn(values,"scope"))state.draft.scope="system";if(!Object.hasOwn(values,"enabled"))state.draft.enabled=false;if(state.provider==="application")Object.assign(state.draft,{path:"*",all_applications:true});}
      state.applicationQuery="";state.applicationOpen=!state.draft.path;
      state.editing=null;state.preview=null;state.error="";state.serviceOpen=false;state.serviceQuery="";
    }
    const options = (values,selected) => values.map(([value,label])=>`<option value="${esc(value)}"${value===selected ? " selected":""}>${esc(label)}</option>`).join("");
    const field = (name,label,value,hint="",extra="") => `<label class="network-rule-field"><span>${esc(c(label))}</span><input name="${name}" value="${esc(value ?? "")}" ${extra}>${hint ? `<small>${esc(c(hint))}</small>`:""}</label>`;
    const select = (name,label,values,value) => `<label class="network-rule-field"><span>${esc(c(label))}</span><select name="${name}">${options(values,value)}</select></label>`;
    function selectedService(rule) {
      if (rule?.custom_service) return null;
      if (rule?.service) return serviceDetails().find(s=>s.id===rule.service) || {id:rule.service,label:rule.service,ports:[],additional_conditions:true};
      if (rule?.selected_service) return serviceDetails().find(s=>s.id===rule.selected_service);
      if (!rule || !rule.ports?.length || typeof rule.ports === "string") return null;
      const ports = JSON.stringify(rule.ports), protocols = JSON.stringify([...(rule.protocols || [])].sort());
      return serviceDetails().find(s=>{const scope=serviceScope(s);return scope && JSON.stringify(scope.ports)===ports && JSON.stringify(scope.protocols)===protocols;});
    }
    function servicesText(rule) {
      const service=selectedService(rule);
      return `${service ? service.id+" · ":""}${service ? servicePortLabel(service) || c("definitionMissing") : portsText(rule.ports) || c("anyService")}${!service ? " · "+(rule.protocols || []).join("/").toUpperCase():""}`;
    }
    function summary(rule) {
      const from=rule.provider === "incoming" ? rule.source || c("anySource") : rule.path==="*" ? c("thisDevice"):appFor(rule).name;
      const to=rule.provider === "incoming" ? `${c("thisDevice")} · ${rule.zone}` : destinationText(rule.destinations) || c("anyDestination");
      return `${c(rule.action || "edit")} · ${from} → ${to} · ${servicesText(rule)} · ${c(rule.lifetime || "permanent")}`;
    }
    function matchingServices() {
      const query=state.serviceQuery.trim().toLowerCase();
      const numeric=/^\d+$/.test(query),number=Number(query);
      return serviceDetails().filter(s=>numeric ? (s.ports || []).some(([range])=>{
        const [start,end=start]=String(range).split("-").map(Number);return number>=start && number<=end;
      }):`${s.id} ${s.label} ${servicePortLabel(s)}`.toLowerCase().includes(query)).slice(0,80);
    }
    function servicePicker(d) {
      const service=selectedService(d), matches=matchingServices();
      return `<section class="network-flow-services"><div class="network-flow-caption"><span class="network-flow-number">03</span><div><h3>${esc(c("services"))}</h3><p>${esc(c("catalogSource"))}</p></div></div>
        <div class="network-service-picker"><div class="network-service-selected"><strong>${esc(service?.label || c("customService"))}</strong><code>${esc(service ? servicePortLabel(service) || c("definitionMissing") : portsText(d.ports) || (d.provider==="incoming" ? c("customHint"):c("anyService")))}</code>${service ? `<button type="button" class="text-button" data-rule-service-custom>${esc(c("clearService"))}</button>`:""}</div>
        <label class="network-service-search"><span class="sr-only">${esc(c("serviceSelection"))}</span><input name="service_query" data-rule-service-search placeholder="${esc(c("chooseService"))}" value="${esc(state.serviceQuery)}" role="combobox" aria-autocomplete="list" aria-expanded="${state.serviceOpen}" aria-controls="network-service-options" ${state.serviceOpen && matches.length ? `aria-activedescendant="network-service-${Math.min(state.serviceIndex,matches.length-1)}"`:""}></label>
        ${state.serviceOpen ? `<div class="network-service-options" id="network-service-options" role="listbox" aria-label="${esc(c("installedServices"))}">${matches.length ? matches.map((s,index)=>{const supported=d.provider==="incoming" || Boolean(serviceScope(s));return `<button type="button" role="option" id="network-service-${index}" aria-selected="${index===state.serviceIndex}" data-rule-service="${esc(s.id)}"${!supported ? " disabled":""}><span><strong>${esc(s.label)}</strong><small>${esc(s.id)}${!supported ? " · "+esc(c("outboundUnsupported")):s.additional_conditions ? " · "+esc(c("additionalConditions")):""}</small></span><code>${esc(servicePortLabel(s) || c("definitionMissing"))}</code></button>`;}).join(""):`<p>${esc(c("noServiceMatch"))}</p>`}</div>`:""}</div>
        ${!service ? `<div class="network-rule-field-pair">${field("ports","customService",portsText(d.ports),"customHint")}${select("protocol","protocols",[["both",c("both")],["tcp","TCP"],["udp","UDP"],...(d.provider!=="incoming" ? [["any",c("anyProtocol")]]:[])],d.protocols?.includes("any") ? "any":d.protocols?.length===2 ? "both":d.protocols?.[0])}</div>`:`<p class="network-rule-note">${esc(c("serviceDefinition"))}</p>`}
        ${state.data?.catalog?.definitions_incomplete ? `<p class="network-rule-warning">${esc(c("serviceUnavailable"))}</p>`:""}</section>`;
    }
    const isIP = rule => rule.provider==="incoming" || rule.path==="*";
    const viewRules = () => (state.data?.rules || []).filter(r=>state.view==="ip" ? isIP(r):!isIP(r));
    function appFor(rule){return state.data?.installedApplications?.items?.find(a=>a.supported && a.path===rule.path) || {name:rule.path ? (state.data?.applications?.find(a=>a.path===rule.path)?.name || c("nativeScope")+" · "+rule.path.split("/").at(-1)):c("chooseApplication"),path:rule.path};}
    function appMark(app){return typeof app.icon==="string" && app.icon.length<=24000 && /^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(app.icon) ? `<img src="${app.icon}" alt="" width="36" height="36">`:identity("application",[app.name,app.path]);}
    function applicationPicker(d){
      const catalog=state.data?.installedApplications || {}, selected=appFor(d), query=state.applicationQuery.toLocaleLowerCase();
      const entries=(catalog.items || []).map((a,index)=>({a,index})).filter(({a})=>`${a.name} ${a.id}`.toLocaleLowerCase().includes(query));
      const open=state.applicationOpen || !d.path;
      return `<div class="network-application-picker"><div class="network-selected-application">${appMark(selected)}<div><strong>${esc(selected.name)}</strong><small>${esc(c("applicationScope"))}</small></div></div>${!open ? `<button type="button" class="secondary" data-rule-application-change>${esc(c("changeApplication"))}</button>`:`<input name="application_query" data-rule-application-search type="search" placeholder="${esc(c("searchApplications"))}" aria-label="${esc(c("searchApplications"))}" value="${esc(state.applicationQuery)}"><div class="network-application-list" role="group" aria-label="${esc(c("installedApplications"))}">${entries.slice(0,256).map(({a,index})=>`<button type="button" data-rule-application="${index}" aria-pressed="${a.supported && a.path===d.path}"${!a.supported ? " disabled":""}>${appMark(a)}<span><strong>${esc(a.name)}</strong><small>${esc(c(a.supported ? "nativeApplication":a.reason==="flatpak" ? "flatpakUnsupported":"launcherUnsupported"))}</small></span>${a.supported && a.path===d.path ? icon("check"):""}</button>`).join("") || `<p>${esc(c(catalog.unavailable ? "catalogUnavailable":"noApplicationMatch"))}</p>`}</div>${catalog.truncated ? `<p class="network-rule-warning">${esc(c("catalogLimited"))}</p>`:""}`}<p class="network-rule-note">${esc(c("applicationCatalogNote"))}</p></div>`;
    }
    function editor() {
      const d=state.draft;if(!d)return "";
      const incoming=d.provider==="incoming", active=canEdit(d.provider);
      return `<dialog data-rule-dialog class="network-rule-editor" aria-label="${esc(c(state.editing ? "editFlow":"newFlow"))}"><header class="network-editor-heading"><div><div class="eyebrow">${esc(c("draftScope"))}</div><h2>${esc(c(state.editing ? "editFlow":"newFlow"))}</h2><p>${esc(c("flowHint"))}</p></div><button type="button" class="text-button" data-rule-close${state.busy ? " disabled":""}>${esc(c("close"))}</button></header><form data-rule-form><fieldset${state.busy ? " disabled":""}>
        <div class="network-editor-basics${state.view==="applications" ? " is-application":""}">${field("name","name",d.name)}${state.view==="ip" ? select("flow_provider","trafficType",[["incoming",c("incomingDirection")],["application",c("outgoingDirection")]],d.provider):""}${select("enabled","configuration",[["true",c("enabled")],["false",c("disabled")]],String(d.enabled))}</div>
        <div class="network-flow-path"><section class="network-flow-endpoint"><div class="network-flow-caption"><span class="network-flow-number">01</span><div><h3>${esc(c("from"))}</h3><p>${esc(c(incoming ? "remoteSource":state.view==="ip" ? "thisDevice":"localApplication"))}</p></div></div>${incoming ? field("source","source",d.source,"sourceHint"):state.view==="ip" ? `<div class="network-local-object">${icon("system")}<strong>${esc(c("thisDevice"))}</strong><small>${esc(c(d.scope==="system" ? "system":"user"))}</small></div>`:applicationPicker(d)}</section><span class="network-flow-arrow" aria-hidden="true">${icon("arrow")}</span><section class="network-flow-endpoint"><div class="network-flow-caption"><span class="network-flow-number">02</span><div><h3>${esc(c("to"))}</h3><p>${esc(c(incoming ? "thisDevice":"destinations"))}</p></div></div>${incoming ? select("zone","zone",(state.data?.catalog?.zones || []).map(z=>[z,z]),d.zone):field("destinations","destinations",destinationText(d.destinations),state.view==="ip" ? "ipOnly":"destinationHint")}</section></div>
        ${servicePicker(d)}<section class="network-flow-decision"><div class="network-flow-caption"><span class="network-flow-number">04</span><h3>${esc(c("decision"))}</h3></div><div class="network-rule-field-pair">${select("action","action",[["deny",c("deny")],["allow",c("allow")]],d.action)}${select("lifetime","lifetime",["permanent","boot","15m","1h"].map(v=>[v,c(v)]),d.lifetime)}</div></section>
        <details class="network-rule-advanced"><summary>${esc(c("advanced"))}</summary><div class="network-rule-field-pair">${select("family","family",[["any",c("any")],["ipv4","IPv4"],["ipv6","IPv6"]],d.family)}${!incoming ? select("scope","scope",[["user",c("user")],["system",c("system")]],d.scope):""}</div>${field("description","description",d.description)}${!incoming && d.path!=="*" ? `<p>${esc(c("nativeScope"))}: <code>${esc(d.path)}</code></p>`:""}</details>
        <div class="network-editor-footer"><div><span class="eyebrow">${esc(c("summary"))}</span><output data-rule-summary>${esc(summary(d))}</output><small>${esc(engine(d.provider))} · ${esc(c(incoming ? "wholeSystem":"allowNotice"))}</small></div><button class="primary" type="submit"${!active ? " disabled":""}>${esc(c("review"))} ${icon("arrow")}</button></div>${!active ? `<p class="network-rule-warning">${esc(c("providerUnavailable"))}</p>`:""}</fieldset></form></dialog>`;
    }
    function review() {
      if(!state.preview)return "";
      return `<dialog data-rule-dialog class="network-rule-review" aria-label="${esc(c("reviewTitle"))}"><div class="eyebrow">${esc(providerName(state.provider))} · ${esc(engine(state.provider))}</div><h2>${esc(c("reviewTitle"))}</h2><p>${esc(c("reviewCopy"))} ${esc(c("applyScope"))}</p><div class="network-rule-change-list">${state.preview.changes.map(change=>`<article><strong>${esc(c(change.operation==="enable" ? "availabilityChange":change.operation==="restore order" ? "restoreOrder":change.operation))} · ${esc(change.rule.name)}</strong><p>${esc(change.operation==="restore order" ? c("restoreOrder"):change.rule.provider ? summary(change.rule):change.rule.name)}</p></article>`).join("")}</div>${state.preview.warnings.map(w=>`<p class="network-rule-warning">${esc(w)}</p>`).join("")}<div class="network-rule-actions"><button class="primary" data-rule-apply${state.busy ? " disabled":""}>${esc(c(state.busy ? "saving":"apply"))}</button><button class="secondary" data-rule-cancel>${esc(c("cancel"))}</button></div></dialog>`;
    }
    function filteredRules() {
      const query=state.search.trim().toLowerCase();
      return viewRules().filter(r=>(state.view==="applications" || state.filterProvider==="all" || r.provider===state.filterProvider) && (!state.filter || (state.filter==="ACTIVE" ? ["SAVED","LOADED","OBSERVED"].includes(r.state):r.state===state.filter)) && (!query || `${JSON.stringify(r)} ${servicesText(r)} ${selectedService(r)?.label || ""}`.toLowerCase().includes(query)));
    }
    function row(rule) {
      const incoming=rule.provider==="incoming", ip=isIP(rule), service=selectedService(rule), app=appFor(rule);
      const label=({SAVED:"savedState",LOADED:"loadedState",OBSERVED:"observedState",EXPIRED:"expiredState",DISABLED:"disabledState",UNAVAILABLE:"unavailableState"})[rule.state] || "savedState";
      const source=incoming ? rule.source || c("anySource"):ip ? c("thisDevice"):app.name;
      const destination=incoming ? `${c("thisDevice")} · ${rule.zone}`:destinationText(rule.destinations) || c("anyDestination");
      const cell=(focus,html)=>`<button class="network-rule-cell" data-rule-action="edit" data-rule-focus="${focus}" data-id="${esc(rule.id)}">${html}</button>`;
      return `<tr data-rule-id="${esc(rule.id)}"><td><input type="checkbox" data-rule-select="${esc(rule.id)}" aria-label="${esc(rule.name)}"${state.selected.has(rule.id) ? " checked":""}></td><td class="network-order"><strong>${incoming ? "IN":"OUT"} ${Number(rule.position)+1}</strong><span>${esc(engine(rule.provider))}</span></td><td><button class="network-rule-switch" data-rule-action="${rule.enabled ? "disable":"enable"}" data-id="${esc(rule.id)}" aria-label="${esc(c(rule.enabled ? "disable":"enable"))} ${esc(rule.name)}" aria-pressed="${rule.enabled}"${!canEdit(rule.provider) ? " disabled":""}><span></span>${esc(c(rule.enabled ? "enabled":"disabled"))}</button><small class="network-rule-state state-${String(rule.state).toLowerCase()}">${esc(c(label))}</small>${rule.observed?.decisions!=null ? `<small>${esc(rule.observed.decisions)} ${esc(c("matches"))}</small>`:""}</td><td>${cell("action",`<span class="network-rule-action action-${esc(rule.action)}">${esc(c(rule.action))}</span>`)}</td><td class="network-rule-name">${cell("name",`<strong>${esc(rule.name)}</strong><small>${esc(c(incoming ? "incomingDirection":"outgoingDirection"))}</small>`)}</td><td><div class="network-rule-source">${!ip ? appMark(app):""}${cell(incoming ? "source":ip ? "flow_provider":"application_query",`<span>${esc(source)}<small>${esc(incoming ? c("wholeSystem"):rule.scope==="system" ? c("system"):Number.isInteger(rule.uid) && rule.uid!==state.data.actor_uid ? `UID ${rule.uid}`:c("user"))}</small></span>`)}</div></td><td>${cell(incoming ? "zone":"destinations",`<span class="network-cell-value">${esc(destination)}</span>`)}</td><td>${cell("service_query",`<strong class="network-service-name">${esc(service?.label || c("customService"))}</strong><code class="network-service-ports">${esc(service ? servicePortLabel(service) || c("definitionMissing"):(portsText(rule.ports) || c("anyService"))+" · "+(rule.protocols || []).join("/").toUpperCase())}</code>`)}</td><td><details class="network-rule-menu"><summary aria-label="${esc(c("edit"))}">···</summary><div>${["edit","duplicate",rule.enabled ? "disable":"enable","up","down","remove"].map(a=>`<button data-rule-action="${a}" data-id="${esc(rule.id)}"${!canEdit(rule.provider) ? " disabled":""}>${esc(c(a))}</button>`).join("")}</div></details></td></tr>`;
    }
    function markup() {
      const data=state.data, filtered=filteredRules(), rows=filtered.slice(state.offset,state.offset+100);
      const unavailable=!data || (state.view==="applications" ? !Number.isInteger(data.providers.application.revision):state.filterProvider!=="all" ? !Number.isInteger(data.providers[state.filterProvider].revision):!viewRules().length && Object.values(data.providers).some(p=>!Number.isInteger(p.revision)));
      return `<section class="network-rules-product" data-network-rules><header class="network-rules-header"><div><div class="eyebrow">${esc(t("nav.network"))}</div><h1>${esc(c(state.view==="ip" ? "ipFiltering":"applicationRules"))}</h1><p>${esc(c(state.view==="ip" ? "ipIntro":"applicationIntro"))}</p></div><button class="primary" data-rule-new${!(state.view==="applications" ? canEdit("application"):state.filterProvider==="all" ? data?.capabilities?.edit:canEdit(state.filterProvider)) ? " disabled":""}>${icon("plus")} ${esc(c("new"))}</button></header>
        <nav class="network-rule-views" aria-label="${esc(c("title"))}">${[["applications","applicationRules"],["ip","ipFiltering"]].map(([view,key])=>`<button data-rule-view="${view}" aria-pressed="${state.view===view}">${icon(view==="ip" ? "network":"applications")} ${esc(c(key))}<span>${data ? data.rules.filter(r=>view==="ip" ? isIP(r):!isIP(r)).length:"—"}</span></button>`).join("")}</nav><div class="network-rules-toolbar">${state.view==="ip" ? `<div class="network-rules-filters" role="group" aria-label="${esc(c("direction"))}">${[["all",c("allDirections")],["incoming",c("incomingDirection")],["application",c("outgoingDirection")]].map(([p,label])=>`<button data-rule-filter-provider="${p}" aria-pressed="${p===state.filterProvider}">${esc(label)}</button>`).join("")}</div>`:""}<input data-rule-search placeholder="${esc(c("searchAll"))}" aria-label="${esc(c("searchAll"))}" value="${esc(state.search)}"><select data-rule-filter aria-label="${esc(c("state"))}">${options([["",c("all")],["ACTIVE",c("active")],["DISABLED",c("disabledState")],["EXPIRED",c("expiredState")]],state.filter)}</select><button class="secondary" data-rule-refresh>${icon("refresh")}</button><label class="secondary network-import">${esc(c("import"))}<input type="file" accept="application/json,.json" data-rule-import hidden></label><details class="network-rule-menu"><summary class="secondary">${esc(c("export"))}</summary><div>${["application","incoming"].map(p=>`<button data-rule-export="${p}"${!Number.isInteger(data?.providers?.[p]?.revision) ? " disabled":""}>${esc(c(p==="application" ? "exportApplications":"exportIncoming"))}</button>`).join("")}</div></details></div>
        <div class="network-rule-feedback" role="status">${esc(state.error || state.feedback || "")}</div>${state.undo ? `<button class="text-button" data-rule-undo>${esc(c("undo"))}</button>`:""}${state.preview ? review():editor()}
        ${["application","incoming"].map(p=>{const count=viewRules().filter(r=>r.provider===p && state.selected.has(r.id)).length;return count ? `<div class="network-rule-bulk"><strong>${esc(providerName(p))} · ${count} ${esc(c("selected"))}</strong>${["enable","disable","remove"].map(a=>`<button class="secondary" data-rule-bulk="${a}" data-provider="${p}">${esc(c(a))}</button>`).join("")}</div>`:"";}).join("")}
        <div class="network-rule-table-wrap"><table class="network-rule-table"><thead><tr><th></th>${["order","configuration","decision","rule","from","to","services"].map(key=>`<th scope="col">${esc(c(key))}</th>`).join("")}<th></th></tr></thead><tbody>${rows.map(row).join("")}</tbody></table>${unavailable ? `<div class="empty-state"><h2>${esc(c("unavailable"))}</h2><p>${esc(c("unavailableCopy"))}</p></div>`:!rows.length ? `<div class="empty-state"><h2>${esc(c(viewRules().length ? "noResults":"empty"))}</h2><p>${esc(c(viewRules().length ? "noResultsCopy":"emptyCopy"))}</p></div>`:""}</div>
        <footer class="network-rule-pagination"><span>${filtered.length} ${esc(c("total"))}</span><button class="text-button" data-rule-page="previous"${!state.offset ? " disabled":""}>${esc(c("previous"))}</button><button class="text-button" data-rule-page="next"${state.offset+100>=filtered.length ? " disabled":""}>${esc(c("next"))}</button></footer><p class="network-rule-note">${esc(c("outgoingOrder"))} ${esc(c("revokeNotice"))}</p>
        ${state.view==="ip" && data?.external?.rules?.length ? `<details class="network-rule-external-disclosure"><summary>${esc(c("external"))} (${data.external.rules.length})</summary><p class="network-rule-note">${esc(c("readOnly"))}</p>${data.external.rules.map(r=>`<article class="network-rule-external"><strong>${esc(r.zone)} · ${esc(r.kind)}</strong><p>${esc(r.value)}</p><small>${esc([r.runtime ? c("runtime"):"",r.permanent ? c("permanentPlane"):""].filter(Boolean).join(" / "))}</small></article>`).join("")}${data.external.truncated ? `<p>${esc(c("limited"))}</p>`:""}</details>`:""}
        ${state.view==="ip" ? `<p class="network-rule-note">${esc(c("noForwarding"))}</p>`:""}${state.exportText ? `<section class="network-rule-export"><h2>${esc(c("exportTitle"))}</h2><p>${esc(c("exportCopy"))}</p><textarea readonly aria-label="${esc(c("exportTitle"))}">${esc(state.exportText)}</textarea><a class="secondary" data-rule-download download="greyward-network-rules.json">${esc(c("exportAll"))}</a><button class="text-button" data-rule-export-close>${esc(c("close"))}</button></section>`:""}</section>`;
    }
    function draw() {
      if(!root?.isConnected)return;
      const focused=root.querySelector(":focus"), selector=focused?.hasAttribute("data-rule-search") ? "[data-rule-search]":focused?.name ? `[name="${focused.name}"]`:null;
      const selection=focused?.selectionStart==null ? null:[focused.selectionStart,focused.selectionEnd];
      const parent=root.parentElement;root.outerHTML=markup();root=parent.querySelector("[data-network-rules]");bind(root);
      const next=selector ? root.querySelector(selector):null;restoringFocus=true;next?.focus();restoringFocus=false;if(selection && next?.setSelectionRange)next.setSelectionRange(...selection);
    }
    async function reload() {await load();state.selected.clear();draw();}
    async function exportDocument(provider=state.provider) {
      if(!["application","incoming"].includes(provider))throw new Error(c("previewError"));
      const page=await readProvider(provider);
      if(page.revision!==state.data.revision)throw new Error(c("previewError"));
      return {schema:"greyward.network.rules-export/v1",provider,rules:page.rules.filter(r=>provider!=="application" || (state.view==="ip" ? r.path==="*":r.path!=="*")).map(({state,owner,position,observed,...rule})=>rule)};
    }
    function readForm() {
      const form=root?.querySelector("[data-rule-form]");if(!form)return state.draft;
      const values=Object.fromEntries(new FormData(form)), d={...state.draft,...values};
      d.provider=state.provider;d.destinations=destinations(values.destinations);
      if(state.view==="ip" && d.provider==="application"){
        d.path="*";d.all_applications=true;
        if(d.destinations.some(v=>!["ip","network"].includes(v.kind)))throw new Error(c("ipRequired"));
      }
      if(values.enabled!=null)d.enabled=values.enabled==="true";
      d.protocols=values.protocol==="both" ? ["tcp","udp"]:[values.protocol || d.protocols?.[0] || "tcp"];
      d.ports=values.ports ?? d.ports;
      const selected=selectedService(state.draft);
      if(selected) {
        if(d.provider==="incoming") {d.service=selected.id;d.ports=[];d.protocols=["tcp","udp"];}
        else {const scope=serviceScope(selected);if(!scope)throw new Error(c("outboundUnsupported"));d.ports=scope.ports;d.protocols=scope.protocols;d.service="";}
      } else d.service="";
      const custom=state.draft.custom_service;
      delete d.application_query;delete d.service_query;delete d.flow_provider;delete d.protocol;delete d.selected_service;delete d.custom_service;
      state.draft={...d,...(selected ? {selected_service:selected.id}:{}),...(custom ? {custom_service:true}:{})};
      return d;
    }
    async function preview(commands,extra={}) {
      const sequence=++previewSequence;
      try {
        state.error="";
        const reviewed=await call("preview",{provider:state.provider,revision:state.data.revision,commands,...extra});
        if(sequence!==previewSequence){await call("cancel",{transaction:reviewed.transaction});return;}
        state.preview=reviewed;
      } catch(error){if(sequence!==previewSequence)return;state.error=error.message || c("previewError");state.preview=null;}
      draw();
    }
    async function apply() {
      if(!state.preview || state.busy)return;
      state.busy=true;draw();
      try {
        const provider=state.provider, saved=await call("apply",{transaction:state.preview.transaction},125000);
        state.undo=saved.undo ? {token:saved.undo,provider}:null;state.preview=null;state.draft=null;state.feedback=c("saved");await load();state.selected.clear();
      }catch(error){state.error=error.message || c("applyError");state.preview=null;}
      finally{state.busy=false;draw();}
    }
    async function cancel() {
      previewSequence++;const transaction=state.preview?.transaction;
      if(transaction){try{await call("cancel",{transaction});}catch(error){state.error=error.message;}}
      state.preview=null;draw();
    }
    async function action(operation,rule) {
      if(!rule || state.busy)return;state.provider=rule.provider;
      if(operation==="edit" || operation==="duplicate") {state.view=isIP(rule) ? "ip":"applications";fresh({...rule,...(operation==="duplicate" ? {name:rule.name+" · "+c("duplicate")}:{})});state.editing=operation==="edit" ? rule.id:null;draw();return;}
      const siblings=state.data.rules.filter(r=>r.provider===rule.provider);
      const position=siblings.findIndex(r=>r.id===rule.id)+(operation==="up" ? -1:1);
      if(["up","down"].includes(operation) && (position<0 || position>=siblings.length))return;
      await preview([{id:rule.id,operation:operation==="remove" ? "delete":["up","down"].includes(operation) ? "move":"enable",...(["up","down"].includes(operation) ? {position}:operation!=="remove" ? {enabled:operation==="enable"}:{})}]);
    }
    function chooseService(id) {
      const service=serviceDetails().find(s=>s.id===id);if(!service || !state.draft)return;
      if(state.provider==="application" && !serviceScope(service))return;
      const d=readForm();state.draft={...d,custom_service:false,selected_service:id,service:state.provider==="incoming" ? id:""};
      const scope=serviceScope(service);if(state.provider==="application"){state.draft.ports=scope.ports;state.draft.protocols=scope.protocols;}
      state.serviceOpen=false;state.serviceQuery="";state.preview=null;previewSequence++;draw();
    }
    function bind(element) {
      root=element;if(!root)return;
      const dialog=root.querySelector("[data-rule-dialog]");
      if(dialog && !dialog.open){restoringFocus=true;dialog.showModal();restoringFocus=false;}
      dialog?.addEventListener("cancel",async e=>{e.preventDefault();if(state.busy)return;const reviewed=Boolean(state.preview);await cancel();if(!reviewed)state.draft=null;draw();});
      root.querySelectorAll("[data-rule-view]").forEach(b=>b.addEventListener("click",()=>{state.view=b.dataset.ruleView;state.filterProvider="all";state.offset=0;state.selected.clear();state.draft=null;state.preview=null;draw();}));
      root.querySelector("[data-rule-application-change]")?.addEventListener("click",()=>{state.applicationOpen=true;draw();root.querySelector("[data-rule-application-search]")?.focus();});
      root.querySelector("[data-rule-application-search]")?.addEventListener("keydown",e=>{if(["Enter","ArrowDown"].includes(e.key)){e.preventDefault();const first=root.querySelector("[data-rule-application]:not([disabled]):not([hidden])");if(e.key==="Enter")first?.click();else first?.focus();}});
      root.querySelector("[data-rule-application-search]")?.addEventListener("input",e=>{
        state.applicationQuery=e.target.value;
        const holder=document.createElement("div");holder.innerHTML=applicationPicker(state.draft);
        const next=holder.querySelector(".network-application-list");
        root.querySelector(".network-application-list").replaceWith(next);bindApplications(next);
      });
      function bindApplications(container){container.querySelectorAll("[data-rule-application]").forEach(b=>b.addEventListener("click",()=>{
        const app=state.data?.installedApplications?.items?.[Number(b.dataset.ruleApplication)];if(!app?.supported || !app.path)return;
        const d=readForm(),previous=appFor(d);state.draft={...d,path:app.path,name:!d.name || d.name===previous.name ? app.name:d.name};state.applicationOpen=false;state.applicationQuery="";previewSequence++;state.preview=null;draw();
      }));}bindApplications(root);
      root.querySelectorAll("details.network-rule-menu").forEach(menu=>menu.addEventListener("toggle",()=>{
        if(!menu.open)return;
        root.querySelectorAll("details.network-rule-menu[open]").forEach(other=>{if(other!==menu)other.open=false;});
        const panel=menu.querySelector("div"), rect=menu.querySelector("summary").getBoundingClientRect();
        panel.style.left=Math.max(8,Math.min(rect.right-panel.offsetWidth,globalThis.innerWidth-panel.offsetWidth-8))+"px";
        panel.style.top=Math.max(8,Math.min(rect.bottom+6,globalThis.innerHeight-panel.offsetHeight-8))+"px";
      }));
      if(state.busy)root.querySelectorAll("button,input,select,textarea").forEach(el=>{if(!el.hasAttribute("data-rule-cancel"))el.disabled=true;});
      root.querySelector("[data-rule-new]")?.addEventListener("click",()=>{state.provider=state.view==="applications" ? "application":state.filterProvider==="application" ? "application":state.filterProvider==="incoming" || canEdit("incoming") ? "incoming":"application";fresh();draw();root.querySelector('[name="name"]')?.focus();});
      root.querySelector("[data-rule-close]")?.addEventListener("click",async()=>{await cancel();state.draft=null;draw();});
      root.querySelectorAll("[data-rule-filter-provider]").forEach(b=>b.addEventListener("click",()=>{state.filterProvider=b.dataset.ruleFilterProvider;state.offset=0;draw();}));
      root.querySelector("[data-rule-refresh]")?.addEventListener("click",reload);
      root.querySelector("[data-rule-filter]")?.addEventListener("change",e=>{state.filter=e.target.value;state.offset=0;draw();});
      root.querySelector("[data-rule-search]")?.addEventListener("input",e=>{state.search=e.target.value;state.offset=0;draw();});
      root.querySelectorAll("[data-rule-select]").forEach(b=>b.addEventListener("change",()=>{b.checked ? state.selected.add(b.dataset.ruleSelect):state.selected.delete(b.dataset.ruleSelect);draw();}));
      root.querySelectorAll("[data-rule-action]").forEach(b=>b.addEventListener("click",()=>action(b.dataset.ruleAction,state.data.rules.find(r=>r.id===b.dataset.id)).then(()=>{if(b.dataset.ruleFocus)root.querySelector(`[name="${b.dataset.ruleFocus}"]`)?.focus();})));
      root.querySelectorAll("[data-rule-bulk]").forEach(b=>b.addEventListener("click",()=>{state.provider=b.dataset.provider;preview(viewRules().filter(r=>r.provider===state.provider && state.selected.has(r.id)).map(r=>({id:r.id,operation:b.dataset.ruleBulk==="remove" ? "delete":"enable",...(b.dataset.ruleBulk!=="remove" ? {enabled:b.dataset.ruleBulk==="enable"}:{})})));}));
      root.querySelector("[data-rule-form]")?.addEventListener("submit",e=>{e.preventDefault();try{const rule=readForm();if(state.view==="applications" && !rule.path)throw new Error(c("chooseApplication"));preview([{operation:rule.dns_exception ? "dns_exception":"upsert",...(state.editing ? {id:state.editing}:{}),rule}]);}catch(error){state.error=error.message;draw();}});
      root.querySelector('[name="flow_provider"]')?.addEventListener("change",e=>{const value=e.target.value,d=readForm();fresh({provider:value,name:d.name,action:d.action,lifetime:d.lifetime,description:d.description,enabled:d.enabled});draw();});
      const search=root.querySelector("[data-rule-service-search]");
      function refreshServiceOptions(){
        // Keep the focused entry and modal alive across native clipboard queries.
        const holder=document.createElement("div");holder.innerHTML=servicePicker(state.draft);
        const next=holder.querySelector(".network-service-options"),old=root.querySelector(".network-service-options");
        if(next){if(old)old.replaceWith(next);else search.parentElement.after(next);next.querySelectorAll("[data-rule-service]").forEach(b=>b.addEventListener("click",()=>chooseService(b.dataset.ruleService)));}else old?.remove();
        const field=search.getBoundingClientRect?.(),bounds=dialog?.getBoundingClientRect?.();
        if(next && field && bounds)next.classList.toggle("opens-up",bounds.bottom-field.bottom<220 && field.top-bounds.top>220);
        search.setAttribute("aria-expanded",String(state.serviceOpen));
        if(state.serviceOpen && matchingServices().length)search.setAttribute("aria-activedescendant",`network-service-${state.serviceIndex}`);else search.removeAttribute("aria-activedescendant");
      }
      search?.addEventListener("input",e=>{state.serviceQuery=e.target.value;state.serviceOpen=true;state.serviceIndex=0;refreshServiceOptions();});
      search?.addEventListener("focus",()=>{if(!restoringFocus && !state.serviceOpen){state.serviceOpen=true;refreshServiceOptions();}});
      search?.addEventListener("keydown",e=>{const list=matchingServices();if(["ArrowDown","ArrowUp"].includes(e.key)){e.preventDefault();state.serviceOpen=true;const delta=e.key==="ArrowDown" ? 1:-1;state.serviceIndex=Math.max(0,Math.min(list.length-1,state.serviceIndex+delta));refreshServiceOptions();}else if(e.key==="Enter" && state.serviceOpen){e.preventDefault();const service=list[state.serviceIndex];if(service)chooseService(service.id);}else if(e.key==="Tab"){state.serviceOpen=false;refreshServiceOptions();}else if(e.key==="Escape" && state.serviceOpen){e.preventDefault();e.stopPropagation();state.serviceOpen=false;refreshServiceOptions();}});
      root.querySelectorAll("[data-rule-service]").forEach(b=>b.addEventListener("click",()=>chooseService(b.dataset.ruleService)));
      root.querySelector("[data-rule-service-custom]")?.addEventListener("click",()=>{const d=readForm();delete d.selected_service;d.service="";state.draft={...d,custom_service:true};state.serviceOpen=false;state.serviceQuery="";draw();});
      root.querySelector("[data-rule-form]")?.addEventListener("input",e=>{if(e.target.hasAttribute("data-rule-service-search") || e.target.hasAttribute("data-rule-application-search"))return;try{readForm();root.querySelector("[data-rule-summary]").textContent=summary(state.draft);previewSequence++;state.preview=null;}catch(error){state.error=error.message;}});
      root.querySelector("[data-rule-apply]")?.addEventListener("click",apply);
      root.querySelector("[data-rule-cancel]")?.addEventListener("click",cancel);
      root.querySelector("[data-rule-undo]")?.addEventListener("click",()=>{state.provider=state.undo.provider;preview([],{undo:state.undo.token});});
      root.querySelectorAll("[data-rule-page]").forEach(b=>b.addEventListener("click",()=>{state.offset=b.dataset.rulePage==="previous" ? Math.max(0,state.offset-100):state.offset+100;draw();}));
      root.querySelectorAll("[data-rule-export]").forEach(b=>b.addEventListener("click",async()=>{try{state.exportText=JSON.stringify(await exportDocument(b.dataset.ruleExport),null,2);}catch(error){state.error=error.message;}draw();}));
      root.querySelector("[data-rule-import]")?.addEventListener("change",async e=>{try{const file=e.target.files?.[0];if(!file || file.size>1048576)throw new Error(c("importError"));const value=JSON.parse(await file.text());if(value.schema!=="greyward.network.rules-export/v1" || !["application","incoming"].includes(value.provider) || !Array.isArray(value.rules) || !value.rules.length || value.rules.length>1024)throw new Error(c("importError"));state.provider=value.provider;await preview(value.rules.map(rule=>({operation:rule.dns_exception ? "dns_exception":"upsert",rule})));}catch(error){state.error=error.message;draw();}});
      root.querySelector("[data-rule-export-close]")?.addEventListener("click",()=>{state.exportText="";draw();});
      root.querySelector("[data-rule-download]")?.addEventListener("click",e=>{const url=URL.createObjectURL(new Blob([state.exportText],{type:"application/json"}));e.currentTarget.href=url;setTimeout(()=>URL.revokeObjectURL(url),1000);});
    }
    return {load,markup,bind,exportDocument,reviewCommands:async commands=>{state.provider="application";await load();await preview(commands);},begin:values=>{state.provider=values?.provider || "application";state.view=values && isIP({...values,provider:state.provider}) ? "ip":"applications";fresh(values);},state};
  }
  globalThis.GREYWARD_NETWORK_RULES = Object.freeze({create,copy:catalogs,destinations,portsText,serviceScope});
})();
