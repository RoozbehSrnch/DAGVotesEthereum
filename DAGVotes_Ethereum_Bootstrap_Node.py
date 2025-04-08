import time
import socket
import threading
import random
import hashlib
import pickle
import queue
from blspy import AugSchemeMPL, G1Element, G2Element

# Configuration
BOOTSTRAP_IP = "127.0.0.1"
BOOTSTRAP_PORT = 5000         # Listening port
PUBLIC_IP = "127.0.0.1"   # Public IP to connect to validators (The public IP of the EC2 instance)
NUM_VALIDATORS = 2            # Number of validators (including Bootstrap)
NUM_SLOTS = 10
NUM_AGGREGATORS = 2
SLOT_DURATION = 12

print_lock = threading.Lock()

class BootstrappingValidator:
    def __init__(self):
        self.ip = BOOTSTRAP_IP
        self.port = BOOTSTRAP_PORT
        self.private_key = AugSchemeMPL.key_gen("Bootstrap".encode().ljust(32, b'\0'))
        self.public_key = self.private_key.get_g1()
        self.validator_id = 0  # Bootstrap is always ID 0
        self.num_validators = NUM_VALIDATORS
        self.max_slots = NUM_SLOTS
        self.slot_duration = SLOT_DURATION
        self.start_time = None
        self.public_keys = []
        self.block_proposers = []
        self.aggregators = []
        self.peers = []
        self.client_sockets = {}
        self.server_socket = None
        self.running = True
        self.keys = {}
        self.current_votes = {}
        self.previous_votes = {}
        self.pending_votes = queue.Queue()
        self.chains = [[{"hash": "GENESIS", "parent": None, "payload": "", "aggregation": None, "slot": -1, "proposer_id": 0, "signature": None}]]
        self.current_slot = -1
        self.has_proposed = False
        self.has_voted = False
        self.has_aggregated = False
        self.message_queue = queue.Queue(maxsize=100)
        self.pending_chain_requests = set()
        self.proposer_boost = int(0.4 * self.num_validators)
        self.proposed_blocks = {0: ("GENESIS", 0)}
        self.aggregations = []
        self.evidences = []
        self.agg_verification_times = []
        self.agg_creation_times = []
        self.propose_event = threading.Event()
        self.vote_event = threading.Event()
        self.aggregate_event = threading.Event()
        self.reset_event = threading.Event()
        self.message_lock = threading.Lock()
        self.phase_complete = threading.Event()

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(NUM_VALIDATORS - 1)
        print(f"Bootstrapping validator listening on {self.ip}:{self.port}")

    def handle_client(self, client_socket, addr):
        while self.running:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break
                sender_id, serialized_message = pickle.loads(data)
                message = self._deserialize_g2_elements(serialized_message)
                with self.message_lock:
                    self.message_queue.put((sender_id, message))
            except Exception:
                break
        if addr in self.client_sockets:
            del self.client_sockets[addr]
        client_socket.close()

    def accept_connections(self):
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                if addr not in self.client_sockets:
                    self.client_sockets[addr] = client_socket
                    threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True).start()
                else:
                    client_socket.close()
            except Exception:
                time.sleep(0.001)

    def collect_initial_validators(self):
        received_public_keys = [(self.public_key, (PUBLIC_IP, self.port))]
        seen_ports = {self.port}
        print(f"Waiting for {NUM_VALIDATORS - 1} more validators (total {NUM_VALIDATORS})...")
        while len(received_public_keys) < NUM_VALIDATORS:
            client_socket, addr = self.server_socket.accept()
            print(f"Connection from {addr}")
            data = client_socket.recv(4096)
            if not data:
                print(f"No data from {addr}, closing")
                client_socket.close()
                continue
            try:
                public_key_bytes, listen_port = pickle.loads(data)
                public_key = G1Element.from_bytes(public_key_bytes)
                if listen_port in seen_ports:
                    print(f"Duplicate port {listen_port} from {addr}, skipping")
                    client_socket.close()
                    continue
                seen_ports.add(listen_port)
                received_public_keys.append((public_key, (addr[0], listen_port)))
                self.client_sockets[addr] = client_socket
                threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True).start()
                print(f"Received public key and port {listen_port} from {addr}, total: {len(received_public_keys)}/{NUM_VALIDATORS}")
            except Exception as e:
                print(f"Error with {addr}: {e}")
                client_socket.close()
        print(f"Collected all {NUM_VALIDATORS} validators: {[(addr[1], str(pk)[:8]) for pk, addr in received_public_keys]}")
        self.distribute_config(received_public_keys)

    def connect_to_peers(self):
        for peer_ip, peer_port in self.peers:
            if peer_port == self.port and peer_ip == PUBLIC_IP:
                continue
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect((peer_ip, peer_port))
                self.client_sockets[(peer_ip, peer_port)] = sock
                print(f"Validator {self.validator_id}: Connected to peer {peer_ip}:{peer_port}")
                threading.Thread(target=self.handle_client, args=(sock, (peer_ip, peer_port)), daemon=True).start()
            except Exception as e:
                print(f"Validator {self.validator_id}: Failed to connect to peer {peer_ip}:{peer_port} - {e}")

    def distribute_config(self, public_keys_with_addrs):
        self.public_keys = [pk for pk, _ in public_keys_with_addrs]
        validator_addresses = [(ip, port) for _, (ip, port) in public_keys_with_addrs]
        public_keys_bytes = [bytes(pk) for pk in self.public_keys]

        config = {
            "validator_id": None,
            "num_validators": self.num_validators,
            "max_slots": self.max_slots,
            "slot_duration": self.slot_duration,
            "block_proposers": [random.randint(0, NUM_VALIDATORS - 1) for _ in range(NUM_SLOTS)],
            "aggregators": [random.sample(range(NUM_VALIDATORS), NUM_AGGREGATORS) for _ in range(NUM_SLOTS)],
            "public_keys": public_keys_bytes,
            "peers": None
        }

        for i, (addr, client_socket) in enumerate(self.client_sockets.items()):
            config["validator_id"] = i + 1
            config["peers"] = [addr for addr in validator_addresses if addr != public_keys_with_addrs[i + 1][1]]
            client_socket.send(pickle.dumps(config))
            print(f"Sent config to {addr} with ID {config['validator_id']}")

        config["validator_id"] = 0
        config["peers"] = validator_addresses[1:]
        self.block_proposers = config["block_proposers"]
        self.aggregators = config["aggregators"]
        self.peers = config["peers"]

        self.start_time = time.time() + 10
        start_msg = {"type": "start_time", "start_time": self.start_time}
        for addr, client_socket in self.client_sockets.items():
            client_socket.send(pickle.dumps(start_msg))
            print(f"Sent start_time to {addr}: {self.start_time}")

        self.proposer_boost = int(0.4 * self.num_validators)
        for vid in range(self.num_validators):
            self.current_votes[vid] = {"block_hash": "GENESIS", "signature": None, "slot": -1, "validator_id": vid}
            self.previous_votes[vid] = {"block_hash": "GENESIS", "signature": None, "slot": -1, "validator_id": vid}

    def _serialize_g2_elements(self, obj):
        if isinstance(obj, G2Element):
            return {"_g2_bytes": bytes(obj), "_is_g2": True}
        elif isinstance(obj, dict):
            return {k: self._serialize_g2_elements(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._serialize_g2_elements(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self._serialize_g2_elements(item) for item in obj)
        return obj

    def _deserialize_g2_elements(self, obj):
        if isinstance(obj, dict):
            if "_g2_bytes" in obj and "_is_g2" in obj and obj["_is_g2"]:
                return G2Element.from_bytes(obj["_g2_bytes"])
            return {k: self._deserialize_g2_elements(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deserialize_g2_elements(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self._deserialize_g2_elements(item) for item in obj)
        return obj

    def broadcast(self, message):
        serialized_message = self._serialize_g2_elements(message)
        msg_data = pickle.dumps((self.validator_id, serialized_message))
        for peer_ip, peer_port in self.peers:
            addr = (peer_ip, peer_port)
            if addr in self.client_sockets:
                try:
                    self.client_sockets[addr].send(msg_data)
                    with print_lock:
                        print(f"Validator {self.validator_id}: Broadcasted to {addr} at time {int(time.time() - self.start_time)}: {message}")
                except Exception as e:
                    print(f"Validator {self.validator_id}: Failed to send to {addr} - {e}")
            else:
                print(f"Validator {self.validator_id}: No socket for peer {addr}")

    def receive_messages(self):
        while self.running:
            for addr, client_socket in list(self.client_sockets.items()):
                try:
                    data = client_socket.recv(4096)
                    if data:
                        sender_id, serialized_message = pickle.loads(data)
                        message = self._deserialize_g2_elements(serialized_message)
                        with self.message_lock:
                            self.message_queue.put((sender_id, message))
                except:
                    continue
            time.sleep(0.001)

    def hash_block(self, parent_hash, payload, evidence, slot, proposer_id):
        evidence_str = str(evidence) if evidence else ''
        data = f"{parent_hash}{payload}{evidence_str}{slot}{proposer_id}"
        return hashlib.sha256(data.encode()).hexdigest()

    def sign(self, data):
        return AugSchemeMPL.sign(self.private_key, data)

    def verify_signature(self, signature, message, public_key):
        return AugSchemeMPL.verify(public_key, message, signature)

    def process_pending_messages(self, deadline):
        while time.time() < deadline:
            try:
                with self.message_lock:
                    sender_id, message = self.message_queue.get_nowait()
                elapsed_time = int(time.time() - self.start_time)
                with print_lock:
                    print(
                        f"Validator {self.validator_id}: Received message from {sender_id} at time {elapsed_time}: {message}")
                if not isinstance(message, dict) or 'type' not in message:
                    continue

                msg_type = message['type']
                if msg_type == "block":
                    verification_start = time.time()
                    block = message["data"]
                    proposer_pk = self.public_keys[block["proposer_id"]]
                    block_hash = block["hash"]
                    computed_hash = self.hash_block(block["parent"], block["payload"], block.get("evidence", None),
                                                    block["slot"], block["proposer_id"])
                    if computed_hash != block_hash:
                        with print_lock:
                            print(f"Validator {self.validator_id}: Block hash mismatch")
                        continue

                    if not self.verify_signature(block["signature"], block_hash.encode(), proposer_pk):
                        with print_lock:
                            print(f"Validator {self.validator_id}: Block signature verification failed")
                        continue

                    if block.get("evidence"):
                        for group in block["evidence"]:
                            content, agg_sig, bitfield = group
                            if content != "empty":
                                agg_pks = [self.public_keys[agg_id] for agg_id, bit in enumerate(bitfield) if bit == 1]
                                agg_message = f"{content['block_hash']}{content['slot']}{content['evidencing_slot']}".encode()
                                if not AugSchemeMPL.aggregate_verify(agg_pks, [agg_message] * len(agg_pks), agg_sig):
                                    with print_lock:
                                        print(
                                            f"Validator {self.validator_id}: Evidence aggregator signature verification failed")
                                    continue
                                voter_pks = [self.public_keys[i] for i, bit in enumerate(content["bitfield"]) if
                                             bit == 1]
                                if not AugSchemeMPL.aggregate_verify(voter_pks,
                                                                     [content["block_hash"].encode()] * len(voter_pks),
                                                                     content["aggregated_signature"]):
                                    with print_lock:
                                        print(
                                            f"Validator {self.validator_id}: Evidence vote aggregation verification failed")
                                    continue

                    verification_time = time.time() - verification_start
                    with print_lock:
                        print(
                            f"Validator {self.validator_id}: Block verification time: {verification_time:.6f} seconds")

                    if block["hash"] not in self.keys:
                        self.keys[block_hash] = block
                        self.update_chains(block)
                        slot = block.get("slot")
                        proposer_id = block.get("proposer_id")
                        if slot is not None and proposer_id is not None:
                            self.proposed_blocks[slot] = (block_hash, proposer_id)

                elif msg_type == "vote":
                    vote = message["data"]
                    voter_id = vote["validator_id"]
                    if not self.verify_signature(vote["signature"], vote["block_hash"].encode(),
                                                 self.public_keys[voter_id]):
                        with print_lock:
                            print(f"Validator {self.validator_id}: Vote signature verification failed from {voter_id}")
                        continue
                    self.current_votes[voter_id] = vote

                elif msg_type == "aggregation":
                    verification_start = time.time()
                    agg = message["data"]
                    generator_id = sender_id
                    evidence = agg["evidence"]
                    vote_aggregation = agg["vote_aggregation"]
                    slot = agg["slot"]

                    evidence_str = f"{evidence['content']}{evidence['signature']}" if evidence else "None"
                    vote_agg_str = (f"{vote_aggregation['block_hash']}{vote_aggregation['aggregated_signature']}"
                                    f"{''.join(map(str, vote_aggregation['bitfield']))}{vote_aggregation['slot']}"
                                    if vote_aggregation else "None")
                    agg_message = f"{evidence_str}{vote_agg_str}{slot}".encode()
                    if not self.verify_signature(agg["aggregator_signature"], agg_message,
                                                 self.public_keys[generator_id]):
                        with print_lock:
                            print(f"Validator {self.validator_id}: Aggregation signature verification failed")
                        continue

                    if evidence:
                        content = evidence["content"]
                        evidence_msg = (f"{content['block_hash']}{content['slot']}{content['evidencing_slot']}".encode()
                                        if content != "empty" else "empty".encode())
                        if not self.verify_signature(evidence["signature"], evidence_msg,
                                                     self.public_keys[generator_id]):
                            with print_lock:
                                print(f"Validator {self.validator_id}: Evidence signature verification failed")
                            continue
                        if content != "empty":
                            voter_pks = [self.public_keys[i] for i, bit in enumerate(content["bitfield"]) if bit == 1]
                            if not AugSchemeMPL.aggregate_verify(voter_pks,
                                                                 [content["block_hash"].encode()] * len(voter_pks),
                                                                 content["aggregated_signature"]):
                                with print_lock:
                                    print(
                                        f"Validator {self.validator_id}: Evidence vote aggregation verification failed")
                                continue
                        self.evidences.append(
                            (content["evidencing_slot"] if content != "empty" else slot, generator_id, evidence))

                    if vote_aggregation:
                        voter_pks = [self.public_keys[i] for i, bit in enumerate(vote_aggregation["bitfield"]) if
                                     bit == 1]
                        if not AugSchemeMPL.aggregate_verify(voter_pks,
                                                             [vote_aggregation["block_hash"].encode()] * len(voter_pks),
                                                             vote_aggregation["aggregated_signature"]):
                            with print_lock:
                                print(f"Validator {self.validator_id}: Vote aggregation verification failed")
                            continue
                        self.aggregations.append((slot, generator_id, vote_aggregation["block_hash"], agg))

                    verification_time = time.time() - verification_start
                    self.agg_verification_times.append(verification_time)
                    agg_size = len(pickle.dumps(self._serialize_g2_elements(agg)))
                    with print_lock:
                        print(
                            f"Validator {self.validator_id}: Aggregation verification time: {verification_time:.6f} seconds")
                        print(f"Validator {self.validator_id}: Aggregation size: {agg_size} bytes")

            except queue.Empty:
                break

    def process_all_pending_votes(self):
        while not self.pending_votes.empty():
            try:
                sender_id, vote = self.pending_votes.get_nowait()
                if vote["slot"] == self.current_slot and self.verify_signature(vote["signature"],
                                                                               vote["block_hash"].encode(),
                                                                               self.public_keys[sender_id]):
                    self.current_votes[sender_id] = vote
            except queue.Empty:
                break

    def create_block(self):
        while self.running:
            self.propose_event.wait()
            if not self.running:
                break
            slot_start = self.start_time + (self.current_slot * self.slot_duration)
            deadline = slot_start + (self.slot_duration / 6)
            self.process_pending_messages(deadline)
            if not self.has_proposed and self.current_slot > 0 and \
                    self.block_proposers[self.current_slot - 1] == self.validator_id:
                creation_start = time.time()
                chain = self.best_chain(for_voting=False)
                parent_block = chain[-1]
                parent_hash = parent_block["hash"]
                payload = str(random.randint(1000, 9999))
                slot = self.current_slot
                proposer_id = self.validator_id

                evidence = None
                if len(chain) >= 2:
                    grandparent_hash = chain[-2]["hash"]
                    prev_slot = self.current_slot - 1
                    valid_evidences = [
                        (slot, gen_id, ev) for slot, gen_id, ev in self.evidences
                        if slot == prev_slot and ev["content"] != "empty" and ev["content"][
                            "block_hash"] == grandparent_hash
                    ]
                    if valid_evidences:
                        ev_groups = {}
                        for ev_slot, agg_id, ev in valid_evidences:
                            content = ev["content"]
                            content_key = (content["block_hash"], str(content["aggregated_signature"]),
                                           ''.join(map(str, content["bitfield"])))
                            if content_key not in ev_groups:
                                ev_groups[content_key] = {"content": content, "signatures": [], "agg_ids": []}
                            ev_groups[content_key]["signatures"].append(ev["signature"])
                            ev_groups[content_key]["agg_ids"].append(agg_id)

                        evidence = []
                        for content_key, group in ev_groups.items():
                            content = group["content"]
                            agg_sigs = group["signatures"]
                            aggregated_sig = AugSchemeMPL.aggregate(agg_sigs)
                            agg_bitfield = [1 if i in group["agg_ids"] else 0 for i in range(self.num_validators)]
                            evidence.append([content, aggregated_sig, agg_bitfield])

                block_hash = self.hash_block(parent_hash, payload, evidence, slot, proposer_id)
                signature = self.sign(block_hash.encode())

                block = {
                    "parent": parent_hash,
                    "payload": payload,
                    "evidence": evidence,
                    "slot": slot,
                    "proposer_id": proposer_id,
                    "hash": block_hash,
                    "signature": signature
                }

                creation_time = time.time() - creation_start
                block_no_payload = block.copy()
                block_no_payload["payload"] = ""
                block_size = len(pickle.dumps(self._serialize_g2_elements(block_no_payload)))
                with print_lock:
                    print(f"Validator {self.validator_id}: Block creation time: {creation_time:.6f} seconds")
                    print(f"Validator {self.validator_id}: Block size (excluding payload): {block_size} bytes")

                self.keys[block_hash] = block
                self.update_chains(block)
                self.proposed_blocks[self.current_slot] = (block_hash, proposer_id)
                self.broadcast({"type": "block", "data": block})
                with print_lock:
                    print(f"\nValidator {self.validator_id} (Proposer) at slot {self.current_slot}:")
                    self.print_tree_weights(False)
                    print(f"Best chain: {[b['hash'][:8] for b in chain]}")
                    print(
                        f"Proposed block {block_hash[:8]} on parent {parent_hash[:8]} with {len(evidence) if evidence else 0} evidence groups")
                self.has_proposed = True
            self.phase_complete.set()
            self.propose_event.clear()

    def vote_on_block(self):
        while self.running:
            self.vote_event.wait()
            if not self.running:
                break
            slot_start = self.start_time + (self.current_slot * self.slot_duration)
            deadline = slot_start + (self.slot_duration * 2 / 3)
            self.process_pending_messages(deadline)
            if not self.has_voted:
                chain = self.best_chain(for_voting=True)
                block_hash = chain[-1]["hash"]

                vote = {
                    "block_hash": block_hash,
                    "signature": self.sign(block_hash.encode()),
                    "slot": self.current_slot,
                    "validator_id": self.validator_id
                }

                self.broadcast({"type": "vote", "data": vote})
                self.current_votes[self.validator_id] = vote
                self.has_voted = True
            self.phase_complete.set()
            self.vote_event.clear()

    def aggregate_votes(self):
        while self.running:
            self.aggregate_event.wait()
            if not self.running:
                break
            slot_start = self.start_time + (self.current_slot * self.slot_duration)
            deadline = slot_start + (self.slot_duration * 5 / 6)
            self.process_pending_messages(deadline)
            self.process_all_pending_votes()
            if not self.has_aggregated and self.validator_id in self.aggregators[self.current_slot]:
                creation_start = time.time()
                my_vote = self.current_votes.get(self.validator_id, {})
                target_block = my_vote.get("block_hash", "GENESIS")
                evidence = None
                if self.current_slot > 0:
                    prev_slot = self.current_slot - 1
                    valid_aggs = [
                        (slot, gen_id, bh, agg) for slot, gen_id, bh, agg in self.aggregations
                        if slot == prev_slot and bh == self.keys[target_block]["parent"]
                    ]
                    if valid_aggs:
                        best_agg = max(valid_aggs, key=lambda x: sum(
                            x[3].get("vote_aggregation", {}).get("bitfield", [0])) if isinstance(x[3], dict) else 0,
                                       default=None)
                        if best_agg and isinstance(best_agg[3], dict) and best_agg[3].get("vote_aggregation"):
                            content = {
                                "block_hash": best_agg[2],
                                "aggregated_signature": best_agg[3]["vote_aggregation"]["aggregated_signature"],
                                "bitfield": best_agg[3]["vote_aggregation"]["bitfield"],
                                "slot": prev_slot,
                                "evidencing_slot": self.current_slot
                            }
                        else:
                            content = "empty"
                    else:
                        content = "empty"
                    evidence_msg = (f"{content['block_hash']}{content['slot']}{content['evidencing_slot']}".encode()
                                    if content != "empty" else "empty".encode())
                    evidence = {
                        "content": content,
                        "signature": self.sign(evidence_msg)
                    }

                votes_for_block = {
                    vid: v for vid, v in self.current_votes.items()
                    if v["block_hash"] == target_block and v["slot"] == self.current_slot and
                       self.verify_signature(v["signature"], v["block_hash"].encode(), self.public_keys[vid])
                }
                vote_aggregation = None
                if votes_for_block:
                    signatures = [vote["signature"] for vote in votes_for_block.values()]
                    aggregated_signature = AugSchemeMPL.aggregate(signatures)
                    bitfield = [1 if vid in votes_for_block else 0 for vid in range(self.num_validators)]
                    vote_aggregation = {
                        "block_hash": target_block,
                        "aggregated_signature": aggregated_signature,
                        "bitfield": bitfield,
                        "slot": self.current_slot
                    }

                aggregation = {
                    "evidence": evidence,
                    "vote_aggregation": vote_aggregation,
                    "slot": self.current_slot
                }
                evidence_str = f"{evidence['content']}{evidence['signature']}" if evidence else "None"
                vote_agg_str = (f"{vote_aggregation['block_hash']}{vote_aggregation['aggregated_signature']}"
                                f"{''.join(map(str, vote_aggregation['bitfield']))}{vote_aggregation['slot']}"
                                if vote_aggregation else "None")
                agg_message = f"{evidence_str}{vote_agg_str}{self.current_slot}".encode()
                aggregation["aggregator_signature"] = self.sign(agg_message)

                creation_time = time.time() - creation_start
                self.agg_creation_times.append(creation_time)
                agg_size = len(pickle.dumps(self._serialize_g2_elements(aggregation)))
                with print_lock:
                    print(f"Validator {self.validator_id}: Aggregation creation time: {creation_time:.6f} seconds")
                    print(f"Validator {self.validator_id}: Aggregation size: {agg_size} bytes")

                self.broadcast({"type": "aggregation", "data": aggregation})
                if evidence:
                    self.evidences.append((content["evidencing_slot"] if evidence[
                                                                             "content"] != "empty" else self.current_slot,
                                           self.validator_id, evidence))
                if vote_aggregation:
                    self.aggregations.append((self.current_slot, self.validator_id, target_block, aggregation))
                self.has_aggregated = True
                with print_lock:
                    print(
                        f"Validator {self.validator_id}'s aggregation: {aggregation}")
            self.phase_complete.set()
            self.aggregate_event.clear()

    def reset_flags(self):
        while self.running:
            self.reset_event.wait()
            if not self.running:
                break
            self.has_proposed = False
            self.has_voted = False
            self.has_aggregated = False
            self.phase_complete.set()
            self.reset_event.clear()

    def process_messages(self):
        while self.running:
            try:
                with self.message_lock:
                    sender_id, message = self.message_queue.get_nowait()
                elapsed_time = int(time.time() - self.start_time)
                with print_lock:
                    print(
                        f"Validator {self.validator_id}: Received message from {sender_id} at time {elapsed_time}: {message}")
                if not isinstance(message, dict) or 'type' not in message:
                    continue

                msg_type = message['type']
                if msg_type == "block":
                    verification_start = time.time()
                    block = message["data"]
                    proposer_pk = self.public_keys[block["proposer_id"]]
                    block_hash = block["hash"]
                    computed_hash = self.hash_block(block["parent"], block["payload"], block["evidence"], block["slot"],
                                                    block["proposer_id"])
                    if computed_hash != block_hash or not self.verify_signature(block["signature"], block_hash.encode(),
                                                                                proposer_pk):
                        continue
                    if block["evidence"]:
                        for group in block["evidence"]:
                            content, agg_sig, bitfield = group
                            if content != "empty":
                                agg_pks = [self.public_keys[agg_id] for agg_id, bit in enumerate(bitfield) if bit == 1]
                                agg_message = f"{content['block_hash']}{content['slot']}{content['evidencing_slot']}".encode()
                                if not AugSchemeMPL.aggregate_verify(agg_pks, [agg_message] * len(agg_pks), agg_sig):
                                    continue
                                voter_pks = [self.public_keys[i] for i, bit in enumerate(content["bitfield"]) if
                                             bit == 1]
                                if not AugSchemeMPL.aggregate_verify(voter_pks,
                                                                     [content["block_hash"].encode()] * len(voter_pks),
                                                                     content["aggregated_signature"]):
                                    continue
                    verification_time = time.time() - verification_start
                    block_no_payload = {k: v for k, v in block.items() if k != "payload"}
                    block_size = len(pickle.dumps(self._serialize_g2_elements(block_no_payload)))
                    with print_lock:
                        print(
                            f"Validator {self.validator_id}: Block verification time: {verification_time:.6f} seconds")
                        print(f"Validator {self.validator_id}: Block size (excluding payload): {block_size} bytes")

                    if block["hash"] not in self.keys:
                        self.keys[block_hash] = block
                        self.update_chains(block)
                        slot = block.get("slot")
                        proposer_id = block.get("proposer_id")
                        if slot is not None and proposer_id is not None:
                            self.proposed_blocks[slot] = (block_hash, proposer_id)

                elif msg_type == "vote":
                    vote = message["data"]
                    voter_id = vote["validator_id"]
                    if self.verify_signature(vote["signature"], vote["block_hash"].encode(),
                                             self.public_keys[voter_id]):
                        if vote["slot"] == self.current_slot and not self.has_voted:
                            self.pending_votes.put((voter_id, vote))
                        else:
                            self.current_votes[voter_id] = vote

                elif msg_type == "aggregation":
                    verification_start = time.time()
                    agg = message["data"]
                    generator_id = sender_id
                    evidence = agg["evidence"]
                    vote_aggregation = agg["vote_aggregation"]
                    slot = agg["slot"]

                    evidence_str = f"{evidence['content']}{evidence['signature']}" if evidence else "None"
                    vote_agg_str = (f"{vote_aggregation['block_hash']}{vote_aggregation['aggregated_signature']}"
                                    f"{''.join(map(str, vote_aggregation['bitfield']))}{vote_aggregation['slot']}"
                                    if vote_aggregation else "None")
                    agg_message = f"{evidence_str}{vote_agg_str}{slot}".encode()
                    if not self.verify_signature(agg["aggregator_signature"], agg_message,
                                                 self.public_keys[generator_id]):
                        continue

                    if evidence:
                        content = evidence["content"]
                        evidence_msg = (f"{content['block_hash']}{content['slot']}{content['evidencing_slot']}".encode()
                                        if content != "empty" else "empty".encode())
                        if not self.verify_signature(evidence["signature"], evidence_msg,
                                                     self.public_keys[generator_id]):
                            continue
                        if content != "empty":
                            voter_pks = [self.public_keys[i] for i, bit in enumerate(content["bitfield"]) if bit == 1]
                            if not AugSchemeMPL.aggregate_verify(voter_pks,
                                                                 [content["block_hash"].encode()] * len(voter_pks),
                                                                 content["aggregated_signature"]):
                                continue
                        self.evidences.append(
                            (content["evidencing_slot"] if content != "empty" else slot, generator_id, evidence))

                    if vote_aggregation:
                        voter_pks = [self.public_keys[i] for i, bit in enumerate(vote_aggregation["bitfield"]) if
                                     bit == 1]
                        if not AugSchemeMPL.aggregate_verify(voter_pks,
                                                             [vote_aggregation["block_hash"].encode()] * len(voter_pks),
                                                             vote_aggregation["aggregated_signature"]):
                            continue
                        self.aggregations.append((slot, generator_id, vote_aggregation["block_hash"], agg))

                    verification_time = time.time() - verification_start
                    self.agg_verification_times.append(verification_time)
                    agg_size = len(pickle.dumps(self._serialize_g2_elements(agg)))
                    with print_lock:
                        print(
                            f"Validator {self.validator_id}: Aggregation verification time: {verification_time:.6f} seconds")
                        print(f"Validator {self.validator_id}: Aggregation size: {agg_size} bytes")

            except queue.Empty:
                time.sleep(0.001)

    def update_chains(self, block):
        parent_hash = block["parent"]
        for i, chain in enumerate(self.chains):
            if chain[-1]["hash"] == parent_hash:
                self.chains[i] = chain + [block]
                return
        for chain in self.chains:
            for j, chain_block in enumerate(chain):
                if chain_block["hash"] == parent_hash:
                    new_chain = chain[:j + 1] + [block]
                    self.chains.append(new_chain)
                    return
        if parent_hash not in self.pending_chain_requests:
            self.pending_chain_requests.add(parent_hash)
            self.broadcast({"type": "request_chain", "data": {"root_block": parent_hash, "end_block": block["hash"]}})

    def build_tree(self):
        tree = {"GENESIS": []}
        all_blocks = set()
        for chain in self.chains:
            for block in chain:
                block_hash = block["hash"]
                if block_hash not in all_blocks:
                    all_blocks.add(block_hash)
                    if block["parent"] is not None:
                        if block["parent"] not in tree:
                            tree[block["parent"]] = []
                        tree[block["parent"]].append(block)
        return tree, all_blocks

    def calculate_branch_weight(self, block_hash, tree, for_voting, votes_dict, visited=None):
        if visited is None:
            visited = set()
        if block_hash in visited:
            return 0
        visited.add(block_hash)
        weight = 0 if self.current_slot == 0 and for_voting else sum(1 for vote in votes_dict.values() if vote["block_hash"] == block_hash)
        if for_voting and block_hash == self.proposed_blocks.get(self.current_slot, (None, None))[0]:
            weight += self.proposer_boost
        children = tree.get(block_hash, [])
        for child in children:
            weight += self.calculate_branch_weight(child["hash"], tree, for_voting, votes_dict, visited)
        return weight

    def print_tree_weights(self, for_voting):
        mode = "Voting" if for_voting else "Proposing"
        slot_block, slot_proposer = self.proposed_blocks.get(self.current_slot, (None, None))
        print(f"Tree structure for {mode} time from Validator {self.validator_id}'s view:")
        if slot_block and for_voting:
            print(f"Current slot {self.current_slot} block: {slot_block[:8]}, Proposer: Validator {slot_proposer}")
        else:
            print(f"Current slot {self.current_slot} block: None" if for_voting else "Block to be proposed.")
        tree, all_blocks = self.build_tree()
        votes_dict = self.previous_votes if for_voting else self.current_votes
        weights = {block_hash: self.calculate_branch_weight(block_hash, tree, for_voting, votes_dict) for block_hash in all_blocks}

        def print_branch(current_hash, indent=""):
            block_votes = sum(1 for vote in votes_dict.values() if vote["block_hash"] == current_hash)
            if self.current_slot == 0 and for_voting:
                block_votes = 0
            boost = self.proposer_boost if (for_voting and current_hash == slot_block) else 0
            line = f"{indent}{current_hash[:8]} ({block_votes}"
            if boost:
                line += f" + {boost} boost"
            line += f") - Branch Weight: {weights[current_hash]}"
            print(line)
            children = sorted(tree.get(current_hash, []), key=lambda x: x["hash"])
            for i, child in enumerate(children):
                prefix = "    --> " if indent else "--> "
                print(f"{indent}{prefix}{child['hash'][:8]}", end=" ")
                print_branch(child["hash"], indent + "    ")

        print_branch("GENESIS")

    def best_chain(self, for_voting=False):
        if not self.chains:
            return [{"hash": "GENESIS", "parent": None, "payload": "", "aggregation": None, "slot": -1, "proposer_id": 0, "signature": None}]
        tree, all_blocks = self.build_tree()
        votes_dict = self.previous_votes if for_voting else self.current_votes
        weights = {block_hash: self.calculate_branch_weight(block_hash, tree, for_voting, votes_dict) for block_hash in all_blocks}
        if for_voting:
            with print_lock:
                self.print_tree_weights(for_voting)

        def select_best_child(current_hash):
            children = tree.get(current_hash, [])
            if not children:
                return [self.keys.get(current_hash, self.chains[0][0])]
            best_children = []
            max_weight = -1
            for child in children:
                child_weight = weights[child["hash"]]
                if child_weight > max_weight:
                    max_weight = child_weight
                    best_children = [child]
                elif child_weight == max_weight:
                    best_children.append(child)
            if not best_children:
                return [self.keys.get(current_hash, self.chains[0][0])]
            if len(best_children) > 1 and for_voting:
                slot_block = self.proposed_blocks.get(self.current_slot, (None, None))[0]
                boosted = [c for c in best_children if c["hash"] == slot_block]
                best_child = boosted[0] if boosted else random.choice(best_children)
            else:
                best_child = best_children[0]
            return [self.keys.get(current_hash, self.chains[0][0])] + select_best_child(best_child["hash"])

        return select_best_child("GENESIS")

    def timekeeper(self):
        deadline = self.start_time + (self.max_slots * self.slot_duration) + (self.slot_duration / 3)
        prev_slot = -1
        while self.running and time.time() <= deadline:
            elapsed_time = int(time.time() - self.start_time)
            self.current_slot = elapsed_time // self.slot_duration
            slot_start = self.start_time + (self.current_slot * self.slot_duration)
            current_offset = elapsed_time - (self.current_slot * self.slot_duration)

            if self.current_slot != prev_slot:
                with print_lock:
                    print(f"===== Validator {self.validator_id}: Slot {self.current_slot} Started =====")
                    proposer_idx = self.current_slot - 1 if self.current_slot > 0 else 0
                    print(f"Validator {self.validator_id}: block proposer of the slot: {'None' if self.current_slot == 0 else self.block_proposers[proposer_idx]}")
                self.previous_votes = self.current_votes.copy()
                prev_slot = self.current_slot

            if current_offset == 0:
                self.has_proposed = False
                self.has_voted = False
                self.has_aggregated = False
                self.phase_complete.clear()
                self.propose_event.set()
                self.phase_complete.wait(timeout=self.slot_duration / 6)
                while time.time() < slot_start + (self.slot_duration / 3):
                    time.sleep(0.01)
            elif current_offset == int(self.slot_duration / 3):
                self.phase_complete.clear()
                self.vote_event.set()
                self.phase_complete.wait(timeout=self.slot_duration / 3)
                while time.time() < slot_start + (2 * self.slot_duration / 3):
                    time.sleep(0.01)
            elif current_offset == int(2 * self.slot_duration / 3):
                self.phase_complete.clear()
                self.aggregate_event.set()
                self.phase_complete.wait(timeout=self.slot_duration / 3)
                while time.time() < slot_start + self.slot_duration:
                    time.sleep(0.01)

            next_time = self.start_time + elapsed_time + 1
            sleep_duration = next_time - time.time()
            if sleep_duration > 0:
                time.sleep(sleep_duration)

        with print_lock:
            print(f"Validator {self.validator_id}: Terminating at slot {self.current_slot}")
        print(
            f"Validator {self.validator_id}: Average aggregation verification time: {sum(self.agg_verification_times) / len(self.agg_verification_times):.6f} seconds")
        print(
            f"Validator {self.validator_id}: Average aggregation creation time: {sum(self.agg_creation_times) / len(self.agg_creation_times):.6f} seconds")
        self.running = False

    def run(self):
        self.start_server()
        self.collect_initial_validators()
        self.connect_to_peers()

        accept_thread = threading.Thread(target=self.accept_connections, daemon=True, name=f"Accept_{self.validator_id}")
        propose_thread = threading.Thread(target=self.create_block, daemon=True)
        vote_thread = threading.Thread(target=self.vote_on_block, daemon=True)
        aggregate_thread = threading.Thread(target=self.aggregate_votes, daemon=True)
        reset_thread = threading.Thread(target=self.reset_flags, daemon=True)
        message_thread = threading.Thread(target=self.process_messages, daemon=True, name=f"MsgProc_{self.validator_id}")
        timekeeper_thread = threading.Thread(target=self.timekeeper, daemon=True)

        accept_thread.start()
        propose_thread.start()
        vote_thread.start()
        aggregate_thread.start()
        reset_thread.start()
        message_thread.start()
        timekeeper_thread.start()

        while time.time() < self.start_time:
            time.sleep(1)
        print(f"Starting blockchain at {self.start_time}")
        timekeeper_thread.join()

if __name__ == "__main__":
    bootstrap = BootstrappingValidator()
    bootstrap.run()
