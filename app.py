from flask import Flask, request, jsonify
from database import db
from models import Subscription, WebhookEvent, WebhookDelivery
from datetime import datetime
import requests
from flask_migrate import Migrate
import os
import threading
import hmac
import hashlib
from queue_worker import event_queue, queue_worker, scheduler
from cleanup_service import cleanup_expired_subscriptions
import json
import redis
import pickle
from flasgger import Swagger

# Connect to Redis
redis_client = redis.StrictRedis(host='redis', port=6379, db=0)

# DB initiation & Migration
app = Flask(_name_)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://webhook_user:supersecret@db:5432/webhooks_db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
with app.app_context():
    db.create_all()

migrate = Migrate(app, db)

# Swagger setup
swagger = Swagger(app, template={
    "swagger": "2.0",
    "info": {
        "title": "Webhook Service API",
        "description": "API for managing webhook subscriptions and deliveries",
        "version": "1.0"
    }
})

# Helper functions for caching


def cache_subscription(sub):
    key = f"subscription:{sub.id}"
    redis_client.set(key, pickle.dumps(sub))


def get_cached_subscription(subscription_id):
    key = f"subscription:{subscription_id}"
    cached = redis_client.get(key)
    if cached:
        return pickle.loads(cached)
    return None


def remove_cached_subscription(subscription_id):
    key = f"subscription:{subscription_id}"
    redis_client.delete(key)


def signature_validity(payload, received_signature, sub_id_key):
    key_bytes = sub_id_key.encode('utf-8')
    payload_bytes = json.dumps(payload, separators=(
        ',', ':'), sort_keys=True).encode('utf-8')
    computed_signature = hmac.new(
        key_bytes, payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed_signature, received_signature)


def start_background_worker(app):
    threading.Thread(target=queue_worker, args=(app,), daemon=True).start()

# API Routes


@app.route('/ingest/<subscription_id>', methods=['POST'])
def intiate_webhook(subscription_id):
    """
    Ingest a webhook event.
    ---
    parameters:
      - name: subscription_id
        in: path
        type: string
        required: true
      - name: x-signature
        in: header
        type: string
        required: true
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            event:
              type: string
            data:
              type: object
    responses:
      200:
        description: Request accepted for processing
    """
    payload = request.get_json()
    event_type = payload.get("event")
    sig = request.headers.get('x-signature')
    sub = get_cached_subscription(subscription_id)

    if not sub:
        sub = Subscription.query.filter_by(id=subscription_id).first()
        if not sub:
            return jsonify({'message': 'Subscription not found'}), 404
        cache_subscription(sub)

    if not signature_validity(payload, sig, sub.secret_key):
        return jsonify({"message": "Invalid signature"}), 403

    event = WebhookEvent(event_type=event_type, payload=payload)
    db.session.add(event)
    db.session.commit()

    event_queue.put({
        "event_id": event.id,
        "subscription_id": subscription_id
    })

    return jsonify({"message": "Request accepted for processing"}), 200


@app.route('/subscriptions', methods=['GET'])
def list_subscriptions():
    """
    List all subscriptions.
    ---
    responses:
      200:
        description: A list of subscriptions
    """
    subs = Subscription.query.all()
    return jsonify([{'id': s.id, 'url': s.target_url, 'event': s.event_type} for s in subs])


@app.route('/add_subscription', methods=['POST'])
def create_subscription():
    """
    Create a new subscription.
    ---
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - target_url
            - event_type
          properties:
            target_url:
              type: string
            event_type:
              type: string
            secret_key:
              type: string
    responses:
      201:
        description: Subscription created
    """
    data = request.json
    sub = Subscription(
        target_url=data['target_url'],
        event_type=data['event_type'],
        secret_key=data.get('secret_key')
    )
    db.session.add(sub)
    db.session.commit()
    return jsonify({'id': sub.id}), 201


@app.route('/webhook', methods=['POST'])
def test_webhook():
    """
    Dummy endpoint to simulate target URL.
    ---
    responses:
      200:
        description: Target reached
    """
    print("Reached the target url")
    return jsonify({"message": "Post reached to target url"})


@app.route('/subscription_deliveries/<subscription_id>', methods=['GET'])
def get_recent_deliveries(subscription_id):
    """
    Get recent deliveries for a subscription.
    ---
    parameters:
      - name: subscription_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: List of deliveries
    """
    deliveries = WebhookDelivery.query.filter_by(subscription_id=subscription_id).order_by(
        WebhookDelivery.created_at.desc()).limit(20).all()
    if not deliveries:
        return jsonify({"message": "No deliveries found for this subscription"}), 404

    return jsonify([
        {
            "event_id": d.event_id,
            "attempt": d.attempt_count,
            "status": d.status,
            "http_code": d.http_code,
            "Error_details": d.Error_details,
            "timestamp": d.created_at.isoformat()
        } for d in deliveries
    ])


@app.route('/delivery_status/<event_id>', methods=['GET'])
def get_delivery_status(event_id):
    """
    Get delivery status of an event.
    ---
    parameters:
      - name: event_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: List of delivery attempts
    """
    deliveries = WebhookDelivery.query.filter_by(
        event_id=event_id).order_by(WebhookDelivery.attempt_count).all()
    if not deliveries:
        return jsonify({"message": "No delivery attempts found for this event"}), 404

    return jsonify([
        {
            "attempt": d.attempt_count,
            "status": d.status,
            "http_code": d.http_code,
            "Error_details": d.Error_details,
            "timestamp": d.created_at.isoformat()
        } for d in deliveries
    ])


@app.route('/update_subscription/<subscription_id>', methods=['PUT'])
def update_subscription(subscription_id):
    """
    Update an existing subscription.
    ---
    parameters:
      - name: subscription_id
        in: path
        type: string
        required: true
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            target_url:
              type: string
            event_type:
              type: string
            secret_key:
              type: string
            is_active:
              type: boolean
    responses:
      200:
        description: Subscription updated
    """
    sub = Subscription.query.filter_by(id=subscription_id).first()
    if not sub:
        return jsonify({"message": "Subscription not found"}), 404

    data = request.json
    sub.target_url = data.get('target_url', sub.target_url)
    sub.event_type = data.get('event_type', sub.event_type)
    sub.secret_key = data.get('secret_key', sub.secret_key)
    sub.is_active = data.get('is_active', sub.is_active)

    db.session.commit()
    cache_subscription(sub)
    return jsonify({"message": "Subscription updated successfully"}), 200


@app.route('/delete_subscription/<subscription_id>', methods=['DELETE'])
def delete_subscription(subscription_id):
    """
    Delete a subscription.
    ---
    parameters:
      - name: subscription_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Subscription deleted
    """
    sub = Subscription.query.filter_by(id=subscription_id).first()
    if not sub:
        return jsonify({"message": "Subscription not found"}), 404

    db.session.delete(sub)
    db.session.commit()
    remove_cached_subscription(subscription_id)
    return jsonify({"message": "Subscription deleted successfully"}), 200


# Start the services
if _name_ == "_main_":
    scheduler.start()
    cleanup_expired_subscriptions(app)
    start_background_worker(app)
    app.run(host='0.0.0.0', port=8000, debug=True)
