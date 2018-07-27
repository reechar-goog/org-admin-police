import base64
import json
import googleapiclient.discovery

crm = googleapiclient.discovery.build("cloudresourcemanager", "v1")

def prevent_org_admin_add(event, context):
    cloudAuditLogMsg = json.loads(base64.b64decode(event['data']).decode('utf-8'))

    org_id = cloudAuditLogMsg['protoPayload']['resourceName']
    policyDeltas = cloudAuditLogMsg['protoPayload']['serviceData']['policyDelta']['bindingDeltas']

    #scan through policy deltas looking for added Organization Admins
    addedMembers = []
    for delta in policyDeltas:
        if delta['action'] == "ADD" and delta['role'] == 'roles/resourcemanager.organizationAdmin':
            addedMembers.append(delta['member'])

    currentPolicy = crm.organizations().getIamPolicy(resource=org_id).execute()
    currentOrgAdmins = None
    for binding in currentPolicy['bindings']:
        if binding['role'] == 'roles/resourcemanager.organizationAdmin':
            currentOrgAdmins = binding['members']
    newOrgAdmins = currentOrgAdmins
    for member in addedMembers:
        newOrgAdmins.remove(member)

    print('The Organization Administrators on current policy: {currentOrgAdmins}'.format(currentOrgAdmins=currentOrgAdmins))
    print('The newly added Organization Administrators: {addedMembers}'.format(addedMembers=addedMembers))
    print('Attempting to remove  newly added Organization Administrators. Resulting Organization Administrators will be: {newOrgAdmins}'.format(newOrgAdmins=newOrgAdmins))

    #creates modified policy with newly added Organization Administrators removed
    modifiedPolicy = {}
    modifiedPolicy['policy'] = currentPolicy
    for index,binding in enumerate(modifiedPolicy['policy']['bindings']):
        if binding['role'] == 'roles/resourcemanager.organizationAdmin':
            modifiedPolicy['policy']['bindings'][index]['members'] = newOrgAdmins

    crm.organizations().setIamPolicy(resource=org_id, body=modifiedPolicy).execute()
    print("Successfully removed newly added Organization Admins")

