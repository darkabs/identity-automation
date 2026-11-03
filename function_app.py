import azure.functions as func
import logging
import json
import asyncio
from azure.identity.aio import ClientSecretCredential
from msgraph.graph_service_client import GraphServiceClient
from msgraph_beta import GraphServiceClient as BetaGraphServiceClient #i need to create a new service client
from msgraph.generated.users.item.user_item_request_builder import UserItemRequestBuilder
from msgraph.generated.users.item.messages.messages_request_builder import MessagesRequestBuilder
from msgraph.generated.identity_protection.risky_users.dismiss.dismiss_post_request_body import DismissPostRequestBody
from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph_beta.generated.models.security.email_url_threat_submission import EmailUrlThreatSubmission
from msgraph_beta.generated.models.security.submission_category import SubmissionCategory
import os
from urllib.parse import quote
from uuid import uuid4
import psycopg
from psycopg.types.json import Jsonb

#get default permissions of registered app
scopes = ['https://graph.microsoft.com/.default']

#Initialize the ClientSecretCredential Class to auth with registered App
credentials = ClientSecretCredential (
    tenant_id= os.environ['TenantID'],
    client_id= os.environ['ClientID'],
    client_secret= os.environ['ClientSecret']
)

#Initialize the graphserviceclient, essentially connect to graph using the application and the permissions defined.
client = GraphServiceClient(
    credentials=credentials,
    scopes=scopes
)
#Initialize the beta graphserviceclient, essentially connect to graph using the application and the permissions defined.
beta_client = BetaGraphServiceClient(
    credentials=credentials,
    scopes=scopes
)

app = func.FunctionApp()

@app.event_hub_message_trigger(
    arg_name="event", 
    event_hub_name="EventHubName",
    connection="EventHubConnection"
    ) 

#def eventhub_trigger(azeventhub: func.EventHubEvent):
#    logging.info('Python EventHub trigger processed an event: %s',
#                azeventhub.get_body().decode('utf-8'))


# This example uses SDK types to directly access the underlying EventData object provided by the Event Hubs trigger.
# To use, uncomment the section below and add azurefunctions-extensions-bindings-eventhub to your requirements.txt file
# Ref: aka.ms/functions-sdk-eventhub-python
#
# import azurefunctions.extensions.bindings.eventhub as eh
# @app.event_hub_message_trigger(
#     arg_name="event", event_hub_name="idalert_eh", connection="undefined"
# )

async def eventhub_trigger(event: func.EventHubEvent):
    try:
        message = event.get_body().decode("utf-8")
        matching_records = get_matching_records(message)
    except(UnicodeDecodeError, json.JSONDecodeError) as error:
        logging.exception("Unable to process event: %s")   
        raise
     
    for match in matching_records:
        #Get relevant fields
        workflow = match.get("workflow")
        record = match.get("record")
        
        if not workflow or record is None:
            logging.warning("Skipping match: missing workflow or record")
            continue
        
        properties = record.get("properties") or {}
        user_upn = properties.get("AccountUpn")
        object_id = properties.get("AccountObjectId")
        recipient_object_id = record.get("RecipientObjectId")
        recipient_email_address = record.get("RecipientEmailAddress")
        internet_message_id = record.get("InternetMessageId")


        if workflow == "identity":
            
            #Validate truthy and run checkAccountStatus
            if user_upn:
                try:           
                #Check if account is enabled
                    accountStatus = await checkAccountStatus(user_upn)
                    logging.info("Is User Account Enabled? %s", accountStatus.account_enabled)               
                except Exception:
                    logging.exception("Account Status Check failed")    
                    
            # Validate truthy and checkUserRisk
            if object_id:
                try:    
                #Check user risk state
                    risk_result = await checkUserRisk(object_id)
                    logging.info("The user's risk detail is %s", risk_result.risk_detail)
                except Exception:
                    logging.exception("Risk Check failed")        

            print("-"*5)
            
            #Validate truthy and revoke user sessions
            if  object_id and user_upn:
                try:
                    attempt_id = await startAudit(
                    user_object_id=object_id,
                    action="revoke_sessions",
                    user_upn=user_upn,
                    alert_id=properties.get("AlertId"),
                    alert_title=properties.get("Title")
                    )
                except Exception:
                    logging.exception("Unable to create audit record")
                    raise
                
                try:
                    result = await revokeSessions(user_upn)
                    logging.info(f"{user_upn} 's session revoked", result.value)
                    
                except Exception:
                    logging.exception("Unable to Revoke user settings")
                    
                    await completeAudit(
                        attempt_id=attempt_id,
                        status="unknown",
                        error_code=type(error).__name__,
                        error_message=str(error)
                    )
                
                else:
                    confirmed = result is not None and result.value is True

                    await completeAudit(
                        attempt_id=attempt_id,
                        status="succeeded" if confirmed else "unknown",
                        error_code=None if confirmed else "UnconfirmedResult",
                        error_message=None if confirmed else "Graph did not confirm success"
                    )

            
        elif workflow == "email":   
        #Validate truthy and run getMessageInfo and buildMessage and reportPhish
            if recipient_object_id and internet_message_id:
                try:
                    
                    getMessage = await getMessageInfo(recipient_object_id, internet_message_id)
                    
                    
                    if getMessage:
                        message = getMessage[0]
                        logging.info ("The message is returned")
                    
                        message_url = buildMessage(recipient_object_id, message.id)
                        
                        if message_url:
                            await reportPhish(recipient_email_address, message_url)
                    else:
                        logging.info("No matching message")                 
                        
                except Exception:
                    logging.exception("Unable to retrieve message or report the email")  
                


criteria = {
    "identity": {
        "Title": [
            "anomalous token",
            "microsoft entra threat intelligence",
            "malicious ip address"
        ],
        "Severity": ["High"]
    },
    "email": {
        "Title": ["spoofed mail"],
        #"Severity": ["High"]
    }
}

def get_matching_records(message):
    new_event = json.loads(message)
    matching_records = []
    
    
    for record in new_event.get("records", []):
        try:
        
            if record.get("category") != "AdvancedHunting-AlertEvidence":
                continue
            
            properties = record.get("properties") or {}
            
            for workflow, workflow_criteria in criteria.items():
                matches = True
                
                for field, allowed_values in workflow_criteria.items():
                    value = properties.get(field, record.get(field))
                    
                    if field == "Title":
                        value = (value or "").lower()
                
                    if value not in allowed_values:
                        matches = False
                        break
                
                if matches:
                    matching_records.append({
                        "workflow": workflow,
                        "record": record
                        })
            
        except Exception as error:
            print(error)            
    return matching_records


async def checkAccountStatus(user_upn):
        #Initiatilize the UsersRequestBuilder to filter the requests
    query_params = UserItemRequestBuilder.UserItemRequestBuilderGetQueryParameters(
        select=["accountEnabled"]
    )
    request_conf = RequestConfiguration(
        query_parameters=query_params
    )
    accountStatus = await client.users.by_user_id(user_upn).get(request_configuration=request_conf)
    if accountStatus:
        return accountStatus
             
async def revokeSessions(user_upn):
    result = await client.users.by_user_id(user_upn).revoke_sign_in_sessions.post()
    return result

async def checkUserRisk(object_id):
    risk_result = await client.identity_protection.risky_users.by_risky_user_id(object_id).get()
    return risk_result
    
async def dismissRisk(user_upn):
    #Initialize the DismissPostRequestBody
    request_body = DismissPostRequestBody(
        user_ids=[user_upn]
    )
    dismiss_result = await client.identity_protection.risky_users.dismiss.post(request_body)
    return dismiss_result

         
async def getMessageInfo(user_upn, internet_message_id):
    escaped_id = internet_message_id.replace("'", "''")
    
    request_body = MessagesRequestBuilder.MessagesRequestBuilderGetQueryParameters(
        select=["internetMessageId","id","subject"],
        filter = f"internetMessageId eq '{escaped_id}'"
    )
    request_config= RequestConfiguration(
        query_parameters=request_body
    )
    result = await client.users.by_user_id(user_upn).messages.get(request_configuration=request_config)
    return (result.value or []) if result else []

def buildMessage(user_upn: str, graph_message_id: str) -> str:
    return (
        "https://graph.microsoft.com/beta/users/"
        f"{quote(user_upn, safe='')}/messages/"
        f"{quote(graph_message_id, safe='')}"
    )
    
    
async def reportPhish(recipient_email_address, message_url):
    request_body = EmailUrlThreatSubmission(
        odata_type = "#microsoft.graph.security.emailUrlThreatSubmission",
        category = SubmissionCategory.Phishing,
        recipient_email_address = recipient_email_address,
        message_url = message_url
    )
    result = await beta_client.security.threat_submission.email_threats.post(request_body)
    return result

def _startAudit(
    user_object_id,
    action,
    user_upn=None,
    alert_id=None,
    alert_title=None,
    invocation_id=None,
    details=None
):
    attempt_id = uuid4()

    connection = psycopg.connect(
        os.environ["POSTGRES_CONNECTION_STRING"],
        connect_timeout=10
    )

    with connection:
        connection.execute(
            """
            INSERT INTO public.identity_response_audit (
                attempt_id,
                alert_id,
                alert_title,
                user_upn,
                user_object_id,
                action,
                invocation_id,
                details
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                attempt_id,
                alert_id,
                alert_title,
                user_upn,
                user_object_id,
                action,
                invocation_id,
                Jsonb(details if details is not None else {})
            )
        )

    return attempt_id

async def startAudit(
    user_object_id,
    action,
    user_upn=None,
    alert_id=None,
    alert_title=None,
    invocation_id=None,
    details=None
):
    return await asyncio.to_thread(
        _startAudit,
        user_object_id,
        action,
        user_upn,
        alert_id,
        alert_title,
        invocation_id,
        details
    )

def _completeAudit(
    attempt_id,
    status,
    error_code=None,
    error_message=None
):
    if status not in ("succeeded", "failed", "unknown"):
        raise ValueError("Invalid completion status")

    connection = psycopg.connect(
        os.environ["POSTGRES_CONNECTION_STRING"],
        connect_timeout=10
    )

    with connection:
        cursor = connection.execute(
            """
            UPDATE public.identity_response_audit
            SET status = %s,
                completed_at = CURRENT_TIMESTAMP,
                error_code = %s,
                error_message = %s
            WHERE attempt_id = %s
              AND status = 'started'
            """,
            (status, error_code, error_message, attempt_id)
        )

        if cursor.rowcount != 1:
            raise ValueError(
                "No started audit record found for this attempt_id"
            )


async def completeAudit(
    attempt_id,
    status,
    error_code=None,
    error_message=None
):
    await asyncio.to_thread(
        _completeAudit,
        attempt_id,
        status,
        error_code,
        error_message
    )