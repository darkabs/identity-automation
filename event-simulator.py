import asyncio
import json

from azure.eventhub import EventData
from azure.eventhub.aio import EventHubProducerClient

EVENT_HUB_CONNECTION_STR = ""
EVENT_HUB_NAME = ""

eventt = {
    "records": [
        {
            "time": "2026-10-21T13:45:00.0000000Z",
            "tenantId": "11111111-2222-4333-8444-555555555555",
            "category": "AdvancedHunting-AlertInfo",
            "properties": {
                "Timestamp": "2026-10-21T13:44:30.0000000Z",
                "AlertId": "sample-alert-entra-multi-0001",
                "Title": "Anomalous token",
                "Category": "CredentialAccess",
                "Severity": "High",
                "ServiceSource": "Microsoft Entra ID Protection",
                "DetectionSource": "Microsoft Entra ID Protection",
                "AttackTechniques": "T1539"
            }
        },
        {
            "time": "2026-10-21T13:45:00.0000000Z",
            "tenantId": "11111111-2222-4333-8444-555555555555",
            "category": "AdvancedHunting-AlertEvidence",
            "properties": {
                "Timestamp": "2026-10-21T13:44:30.0000000Z",
                "AlertId": "sample-alert-entra-multi-0001",
                "Title": "Anomalous token",
                "EntityType": "User",
                "EvidenceRole": "Impacted",
                "AccountName": "Ambrose",
                "AccountDomain": "",
                "AccountUpn": "",
                "AccountObjectId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "Severity": "High"
            }
        },
        {
            "time": "2026-10-21T13:45:00.0000000Z",
            "tenantId": "11111111-2222-4333-8444-555555555555",
            "category": "AdvancedHunting-AlertEvidence",
            "properties": {
                "Timestamp": "2026-10-21T13:44:30.0000000Z",
                "AlertId": "sample-alert-entra-multi-0001",
                "Title": "Anomalous token",
                "EntityType": "User",
                "EvidenceRole": "Impacted",
                "AccountName": "TestUser2",
                "AccountDomain": "",
                "AccountUpn": "",
                "AccountObjectId": "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
                "Severity": "High"
            }
        },
        {
            "time": "2026-10-21T13:45:00.0000000Z",
            "tenantId": "11111111-2222-4333-8444-555555555555",
            "category": "AdvancedHunting-AlertEvidence",
            "properties": {
                "Timestamp": "2026-10-21T13:44:30.0000000Z",
                "AlertId": "sample-alert-entra-multi-0001",
                "Title": "Anomalous token",
                "EntityType": "User",
                "EvidenceRole": "Impacted",
                "AccountName": "TestUser3",
                "AccountDomain": "",
                "AccountUpn": "",
                "AccountObjectId": "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa",
                "Severity": "High"
            }
        }
    ]
}

event = {
   
  "records": [
    {
      "time": "2026-10-15T13:45:00.0000000Z",
      "tenantId": "11111111-2222-4333-8444-555555555555",
      "category": "AdvancedHunting-AlertInfo",
      "properties": {
        "Timestamp": "2026-10-15T13:44:30.0000000Z",
        "AlertId": "sample-alert-entra-0001",
        "Title": "Anomalous token",
        "Category": "CredentialAccess",
        "Severity": "High",
        "ServiceSource": "Microsoft Entra ID Protection",
        "DetectionSource": "Microsoft Entra ID Protection",
        "AttackTechniques": "T1539"
      }
    },
    {
      "time": "2026-10-15T13:45:00.0000000Z",
      "tenantId": "11111111-2222-4333-8444-555555555555",
      "category": "AdvancedHunting-AlertEvidence",
      "properties": {
        "Timestamp": "2026-10-15T13:44:30.0000000Z",
        "AlertId": "sample-alert-entra-0001",
        "Title": "Anomalous token",
        "EntityType": "User",
        "EvidenceRole": "Impacted",
        "AccountName": "",
        "AccountDomain": "",
        "AccountUpn": "",
        "AccountObjectId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "Severity": "High",
        "ServiceSource": "Microsoft Entra ID Protection",
        "DetectionSource": "Microsoft Entra ID Protection"
      }
    }
  ]
}

eventtt = {
    "records" :[
        {
        "Timestamp":"2026-10-27T19:30:16.0000000Z",
        "SenderFromAddress":"lisa.poff@edustate.edu",
        "SenderObjectId":"7b466ef3fa-5f0e-423a-b18f-a41f54cf4b58",
        "RecipientObjectId":"7b466ef3fa-5f0e-423a-b18f-a41f54cf4b58",
        "ReportId":"f6214937-ee16-4a0000-0b39-08df3460b85b-8854904122859958123-1",
        "InternetMessageId":"<09441a07.08cfa5f4.1793129411942@edustate.edu>",
        "NetworkMessageId":"f621499937-ee16-4a00-0b39-08df3460b85b",
        "RecipientEmailAddress":"lisa.poff@edustate.edu",
        "SenderMailFromAddress":"lisa.poff@edustate.edu",
        "Subject":"Completed: Complete with Docusign | Contractual Agreement: edustate NDA-Q4-2026 Ref 6e60f499da",
        "Title":"Spoofed Mail",
        "category": "AdvancedHunting-AlertEvidence"
        }
    ]
}

json_event = json.dumps(eventtt)

async def run():
    # Create a producer client to send messages to the event hub.
    # Specify a connection string to your event hubs namespace and
    # the event hub name.
    producer = EventHubProducerClient.from_connection_string(
        conn_str=EVENT_HUB_CONNECTION_STR, eventhub_name=EVENT_HUB_NAME
    )
    async with producer:
        # Create a batch.
        event_data_batch = await producer.create_batch()

        # Add events to the batch.
        event_data_batch.add(EventData(json_event))

        # Send the batch of events to the event hub.
        await producer.send_batch(event_data_batch)

asyncio.run(run())