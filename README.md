# O-RANClaw: Disrupting E2 Nodes via MitM Fuzzing

<p align="center">
  <img src="./docs/Logo1.jpeg" alt="logo" width="250"/>
</p>

**O-RANClaw** is a structure- and semantic-aware, man-in-the-middle (MitM) fuzzing framework that targets the **E2 interface** in O-RAN. Positioned between xApps and the RIC, O-RANClaw mutates, and duplicates E2 messages to explore and disrupt gNB behavior.  

It is specifically designed to:
- Take into account ASN.1 structural and semantic constraints when mutating packets.
- Systematically explore state transitions and optimize mutation strategies based on coverage.
- Evaluate both the RIC and gNB implementations by simulating xApp manipulations.

In our experiments with **FlexRIC**, **OpenAirInterface**, and **ns-3**, O-RANClaw discovered **65 unique bugs** (7 CVEs already assigned):  
- 28 in FlexRIC  
- 37 in base station implementations (OpenAirInterface and ns-3 simulator)  

O-RANClaw demonstrates that structure- and semantic-aware fuzzing of the E2 interface is highly effective at revealing vulnerabilities in O-RAN components.



![oran-containers-logo](./docs/DesignNoB.png)

## Threat Model

O-RANClaw models the attack scenario where:
1. A malicious or compromised xApp communicates with the RIC.
2. O-RANClaw intercepts E2 messages at the RIC–xApp boundary.
3. Mutated or replayed messages disrupt the gNB’s control or data plane.

---

## Repository Structure

This repository provides am example to deploy :
1. **O-RANClaw Core** – The MitM interception and mutation engine for E2 messages.
2. **Containerized Testbed** – A reproducible Docker Compose deployment of the full O-RAN ecosystem for fuzzing experiments:
   - **5G Core Network** (Open5GS)
   - **gNB (DU, CU-CP, CU-UP)** via OpenAirInterface
   - **UE simulator** for RF simulation
   - **Near-Realtime RIC** (FlexRIC)
   - Example xApps for monitoring/control

The deployment scripts allow anyone to **reproduce the experiments** described in our paper.


This repository provides a containerized deployment solution for Open Radio Access Network (ORAN) using Docker Compose. The `docker-compose.yaml` file orchestrates the deployment of all the necessary software components, including the core network, gNB (DU, CU-CP, CU-UP), UE simulator, and near-realtime RIC agent:

* **5G Core Network:** The core network is implemented using the open5gs software. Open5GS is an open-source project that provides a complete 3GPP-compliant 5G core network solution. It includes various network functions such as AMF, SMF, UPF, NRF, and more. The core network is responsible for handling user authentication, session management, and data forwarding between the gNB and external networks.

* **gNB (DU, CU-CP, CU-UP):** The gNB (Next Generation Node B) is the base station in the ORAN architecture. It is implemented using the OpenAirInterface (OAI) software. OAI is an open-source project that provides a complete software implementation of the 4G/5G radio access network. The gNB is split into three components:
  - **Distributed Unit (DU):** The DU is responsible for the lower layers of the radio protocol stack, including the physical layer (PHY) and the medium access control (MAC) layer. It handles the baseband processing and communicates with the CU-CP and CU-UP.
  
  - **Central Unit - Control Plane (CU-CP):** The CU-CP handles the control plane functions of the gNB. It manages the radio resource control (RRC) protocol and communicates with the core network for signaling purposes.
  
  - **Central Unit - User Plane (CU-UP):** The CU-UP handles the user plane functions of the gNB. It processes the user data packets and forwards them between the DU and the core network.
  
* **UE Simulator:** The UE (User Equipment) simulator is used to emulate the behavior of mobile devices in the ORAN network. It connects to gNB via RF simulation and core network. You can access the UE simulator container to simulate various scenarios and load conditions (e.g., `iperf3`).

* **Near-Realtime RIC Agent:** The near-realtime RIC agent is implemented using the FlexRIC software. FlexRIC is an open-source platform that provides a flexible and extensible framework for developing and deploying RAN intelligent controllers in an ORAN environment. The near-realtime RIC agent is responsible for managing and orchestrating the xAPPs, as well as providing interfaces for external components to interact with the RIC.
* **xAPPs:** xAPPs (ORAN Applications) are software applications that run on top of the near-realtime RIC (RAN Intelligent Controller). They provide various functionalities and services to optimize and enhance the performance of the ORAN network. Examples of xAPPs include traffic steering, quality of service (QoS) optimization, and radio resource management.



### 1 - Install latest docker and docker composer

```python
./requirements.sh

# Pull the components for reproduction
docker pull researchanon2025/oai-components:v1.0
docker pull researchanon2025/flexric-components:v1.0
```



#### 2 - Start Core Network

Run the command below in a separate terminal and wait until you see successful UDR related logs:

```bash
docker compose --profile core up # Terminal 1 - Core Network
```

Successful UDR logs:

```bash
udr-1    | 04/12 07:58:12.304: [sbi] INFO: [6250a1de-f8a2-41ee-bdd9-0f6b7e1be1b5] NF registered [Heartbeat:10s] (../lib/sbi/nf-sm.c:221)
udm-1    | 04/12 07:58:12.304: [sbi] INFO: (NRF-notify) NF registered [6250a1de-f8a2-41ee-bdd9-0f6b7e1be1b5:1] (../lib/sbi/nnrf-handler.c:924)
udm-1    | 04/12 07:58:12.304: [sbi] INFO: [UDR] (NRF-notify) NF Profile updated [6250a1de-f8a2-41ee-bdd9-0f6b7e1be1b5:1] (../lib/sbi/nnrf-handler.c:938)
nrf-1    | 04/12 07:58:12.304: [nrf] INFO: [68e13194-f8a2-41ee-a707-db685e0fa5ce] Subscription created until 2024-04-13T07:58:12.304328+00:00 [validity_duration:86400] (../src/nrf/nnrf-handler.c:445)
udr-1    | 04/12 07:58:12.304: [sbi] INFO: [68e13194-f8a2-41ee-a707-db685e0fa5ce] Subscription created until 2024-04-13T07:58:12.304328+00:00 [duration:86400,validity:86399.999815,patch:43199.999907] (../lib/sbi/nnrf-handler.c:708)
```



#### 3 - Add UE Subscribers

Add sample UE subscribers to the core network so tha the UE Simulator can register to the network:

```python
./scripts/add_subcribers.sh
```

A successful output is shown below:

```bash
{
  acknowledged: true,
  insertedId: ObjectId('6618ec5e2d06d1bb877b2da9')
}
Done!
```

**Note that you can modify the details of UE SIM card (imsi, key, opc, apn) in the files `gnb-oai.yaml` and `scripts/add_subcribers.sh`**



#### 4 - Start ORAN gNB + UE Simulation + Near Realtime RIC

Run the command below in a separate terminal and wait until you see successful UE related logs:

```bash
docker compose --profile gnb-rfsim up # Terminal 2 - gNB + UE Simulation + Near Realtime RIC
```

Successful UE logs:

```bash
oai-ue-rfsimu-2-1  | [NR_PHY]   ============================================
oai-ue-rfsimu-2-1  | [NR_PHY]   Harq round stats for Downlink: 2735/1/0
oai-ue-rfsimu-2-1  | [NR_PHY]   ============================================
```

Note that two simulated UEs are started (containers `oai-ue-rfsimu-1-1` and `oai-ue-rfsimu-2-1`). You can add or remove UEs from the simulation by modifying file `gnb-oai.yaml`.



#### 5 - Run commands in the UE (iperf)

###### UE to Core Network

You can test UE Uplink/Downlink transfer speed by running iperf against the core network, which has default IP address of `10.45.0.1`:

```bash
docker compose exec -it oai-ue-rfsimu-1 iperf3 -c 10.45.0.1 -t0 # Terminal 3 - UE to Core Transfer
```

If the command is successful and the UE is registered to the core network, iperf should indicate a bitrate of about 100mbits/sec as shown below:

```bash
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-1.65   sec  22.2 MBytes   113 Mbits/sec    0             sender
```

###### Core Network to UE

Similarly, you can run iperf against UEs, which are usually registered to IP addresses `10.45.0.2` or `10.45.0.3`:

```bash
docker compose exec -it upf iperf3 -c 10.45.0.3 -t0 # Terminal 3 - Core to UE Transfer
```



#### 6 - Start xAPP

Start a [xAPP KPI monitoring](https://gitlab.eurecom.fr/mosaic5g/flexric/-/blob/master/examples/xApp/c/monitor/xapp_kpm_moni.c?ref_type=heads) example by running the command below:

```bash
docker compose --profile xapp up # Terminal 4 - xAPP
```

The xAPP informs the downlink and uplink throuput of all connected UEs as shown below:

```bash
xapp-kpm-monitor-1  | ran_ue_id = 1
xapp-kpm-monitor-1  | DRB.RlcSduDelayDl = 6014.82 [μs]
xapp-kpm-monitor-1  | DRB.UEThpDl = 250493.20 [kbps]
xapp-kpm-monitor-1  | DRB.UEThpUl = 4843.06 [kbps]
xapp-kpm-monitor-1  | RRU.PrbTotDl = 354196 [PRBs]
xapp-kpm-monitor-1  | RRU.PrbTotUl = 30572 [PRBs]
```


#### Image Information
This deployment uses the following Docker images for reproducibility:

- OAI Components: researchanon2025/oai-components:v1.0 (gNB, UE simulation)
- FlexRIC Components: researchanon2025/flexric-components:v1.0 (Near-RT RIC, xApps)
- Core Network: Standard Open5GS images from Docker Hub

These images contain all necessary components built from:

* OpenAirInterface (OAI) develop branch
* FlexRIC framework for O-RAN RIC functionality


#### System Requirements

RAM: Minimum 8GB, Recommended 16GB
CPU: Minimum 4 cores, Recommended 8+ cores
Storage: At least 20GB free space for images and containers
OS: Linux (tested on Ubuntu 20.04/22.04)

#### Logs and Debugging

``` bash
# Check core network logs
docker compose logs -f amf

# Check gNB logs
docker compose logs -f oai-cu-cp
docker compose logs -f oai-cu-up
docker compose logs -f oai-cu-du

# Check UE logs
docker compose logs -f oai-ue-rfsimu-1

# Check RIC logs
docker compose logs -f nearRT-RIC

```