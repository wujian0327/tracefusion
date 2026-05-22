import argparse
import csv
from collections import defaultdict
import networkx as nx
import matplotlib.pyplot as plt

def generate_topology(csv_file, output_img="topology.png"):
    edges = defaultdict(int)
    nodes = set()
    protocol_edges = defaultdict(set)
    # 每条有向边第一次出现时间（同时考虑 Request/Response）
    edge_first_seen = {}

    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            client_full = row.get('client')
            server_full = row.get('server')
            protocol = row.get('protocol_type')
            msg_type = row.get('msg_type')
            timestamp = row.get('timestamp', '')

            if not client_full or not server_full:
                continue

            # 过滤数据库噪声边（与 lineage/pure_timing 一致）
            if '172.17.0.11' in client_full or '172.17.0.11' in server_full:
                continue

            # 去掉端口号，只保留 IP
            client_ip = client_full.split(':')[0]
            server_ip = server_full.split(':')[0]

            if msg_type not in {"Request", "Response"}:
                continue

            # Request: client -> server
            # Response: server -> client（返回方向）
            if msg_type == "Request":
                edge = (client_ip, server_ip)
                protocol_label = f"{protocol}-Req" if protocol else "Req"
            else:
                edge = (server_ip, client_ip)
                protocol_label = f"{protocol}-Res" if protocol else "Res"

            edges[edge] += 1
            protocol_edges[edge].add(protocol_label)
            nodes.add(client_ip)
            nodes.add(server_ip)

            if edge not in edge_first_seen:
                edge_first_seen[edge] = timestamp
            elif timestamp and edge_first_seen[edge] and timestamp < edge_first_seen[edge]:
                edge_first_seen[edge] = timestamp

    # 按首次出现时间排序，生成序号
    sorted_edges = sorted(edge_first_seen.items(), key=lambda x: x[1])
    edge_order = {edge: idx + 1 for idx, (edge, _) in enumerate(sorted_edges)}

    G = nx.DiGraph()
    for node in nodes:
        G.add_node(node)
    for (src, dst), count in edges.items():
        protocols = ", ".join(sorted(protocol_edges[(src, dst)]))
        order = edge_order.get((src, dst), '')
        label = f"[{order}] {protocols}" if order != '' else protocols
        G.add_edge(src, dst, weight=count, label=label)

    pos = nx.spring_layout(G, k=1.5, iterations=50)

    plt.figure(figsize=(12, 8))
    ax = plt.gca()

    nx.draw_networkx_nodes(G, pos, node_size=2000, node_color='lightblue', alpha=0.9, ax=ax)
    nx.draw_networkx_edges(G, pos, edge_color='gray', arrows=True, arrowsize=30, width=1.5,
                           connectionstyle='arc3,rad=0.1',
                           min_source_margin=30, min_target_margin=30, ax=ax)
    nx.draw_networkx_labels(G, pos, font_size=10, font_weight='bold', ax=ax)

    # 将标签偏移到线外侧（垂直方向偏移）
    edge_labels = nx.get_edge_attributes(G, 'label')
    OFFSET = 0.08
    for (u, v), lbl in edge_labels.items():
        x1, y1 = pos[u]
        x2, y2 = pos[v]
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        dx, dy = x2 - x1, y2 - y1
        length = (dx ** 2 + dy ** 2) ** 0.5
        if length > 0:
            # 垂直于边方向的单位向量
            px, py = -dy / length, dx / length
            lx, ly = mx + px * OFFSET, my + py * OFFSET
        else:
            lx, ly = mx, my
        ax.text(lx, ly, lbl, fontsize=8, ha='center', va='center',
                bbox=dict(boxstyle='round,pad=0.2', facecolor='white', edgecolor='none', alpha=0.8))

    plt.title("Network Topology")
    plt.axis('off')

    plt.savefig(output_img, dpi=300, bbox_inches='tight')
    print(f"Topology graph saved as {output_img}")
    # 在无图形环境下避免阻塞；如需弹窗可手动启用 plt.show()
    # plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a topology graph from cleaned RPC CSV.")
    parser.add_argument(
        "--csv-file",
        default="data/pcap_cleaned_data.csv",
        help="Path to cleaned CSV produced by pcap_to_cleaned.py or ebpf_to_cleaned.py.",
    )
    parser.add_argument(
        "--output",
        default="topology.png",
        help="Path to write the topology PNG.",
    )
    args = parser.parse_args()
    generate_topology(args.csv_file, args.output)
