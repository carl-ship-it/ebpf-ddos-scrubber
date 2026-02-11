import React, { useState } from 'react';
import {
  Card,
  Table,
  Button,
  Modal,
  Form,
  InputNumber,
  Select,
  Space,
  message,
  Popconfirm,
  Tag,
} from 'antd';
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import * as api from '../api/client';
import type { AttackSignature } from '../types';

const protoOptions = [
  { label: 'Any', value: 0 },
  { label: 'TCP (6)', value: 6 },
  { label: 'UDP (17)', value: 17 },
  { label: 'ICMP (1)', value: 1 },
];

const SignaturesPage: React.FC = () => {
  const [signatures, setSignatures] = useState<AttackSignature[]>([]);
  const [modalOpen, setModalOpen] = useState(false);
  const [form] = Form.useForm<AttackSignature>();

  const columns: ColumnsType<AttackSignature> = [
    {
      title: '#',
      dataIndex: 'index',
      key: 'index',
      width: 60,
    },
    {
      title: 'Protocol',
      dataIndex: 'protocol',
      key: 'protocol',
      width: 80,
      render: (p: number) => {
        if (p === 6) return <Tag color="blue">TCP</Tag>;
        if (p === 17) return <Tag color="orange">UDP</Tag>;
        if (p === 1) return <Tag color="green">ICMP</Tag>;
        return <Tag>Any</Tag>;
      },
    },
    {
      title: 'Flags',
      key: 'flags',
      width: 100,
      render: (_: unknown, r: AttackSignature) =>
        r.flagsMask ? `mask=0x${r.flagsMask.toString(16)} match=0x${r.flagsMatch.toString(16)}` : '--',
    },
    {
      title: 'Src Port',
      key: 'srcPort',
      width: 120,
      render: (_: unknown, r: AttackSignature) =>
        r.srcPortMin || r.srcPortMax
          ? `${r.srcPortMin}-${r.srcPortMax}`
          : 'any',
    },
    {
      title: 'Dst Port',
      key: 'dstPort',
      width: 120,
      render: (_: unknown, r: AttackSignature) =>
        r.dstPortMin || r.dstPortMax
          ? `${r.dstPortMin}-${r.dstPortMax}`
          : 'any',
    },
    {
      title: 'Pkt Size',
      key: 'pktLen',
      width: 120,
      render: (_: unknown, r: AttackSignature) =>
        r.pktLenMin || r.pktLenMax
          ? `${r.pktLenMin}-${r.pktLenMax}B`
          : 'any',
    },
    {
      title: 'Payload Hash',
      dataIndex: 'payloadHash',
      key: 'payloadHash',
      width: 120,
      render: (h: number) => (h ? `0x${h.toString(16)}` : '--'),
    },
  ];

  const handleAdd = async () => {
    try {
      const values = await form.validateFields();
      values.index = signatures.length;
      await api.setAttackSignature(values);
      setSignatures([...signatures, values]);
      setModalOpen(false);
      form.resetFields();
      message.success('Signature added');
    } catch (err) {
      message.error(`Failed: ${err}`);
    }
  };

  const handleClearAll = async () => {
    try {
      await api.clearAttackSignatures();
      setSignatures([]);
      message.success('All signatures cleared');
    } catch (err) {
      message.error(`Failed: ${err}`);
    }
  };

  return (
    <Card
      title="Attack Signatures"
      extra={
        <Space>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>
            Add Signature
          </Button>
          <Popconfirm title="Clear all signatures?" onConfirm={handleClearAll}>
            <Button danger icon={<DeleteOutlined />}>
              Clear All
            </Button>
          </Popconfirm>
        </Space>
      }
    >
      <Table
        columns={columns}
        dataSource={signatures}
        rowKey="index"
        size="small"
        pagination={false}
      />

      <Modal
        title="Add Attack Signature"
        open={modalOpen}
        onOk={handleAdd}
        onCancel={() => setModalOpen(false)}
        width={600}
      >
        <Form form={form} layout="vertical" initialValues={{ protocol: 0 }}>
          <Form.Item name="protocol" label="Protocol">
            <Select options={protoOptions} />
          </Form.Item>

          <Space>
            <Form.Item name="flagsMask" label="TCP Flags Mask">
              <InputNumber min={0} max={255} />
            </Form.Item>
            <Form.Item name="flagsMatch" label="TCP Flags Match">
              <InputNumber min={0} max={255} />
            </Form.Item>
          </Space>

          <Space>
            <Form.Item name="srcPortMin" label="Src Port Min">
              <InputNumber min={0} max={65535} />
            </Form.Item>
            <Form.Item name="srcPortMax" label="Src Port Max">
              <InputNumber min={0} max={65535} />
            </Form.Item>
          </Space>

          <Space>
            <Form.Item name="dstPortMin" label="Dst Port Min">
              <InputNumber min={0} max={65535} />
            </Form.Item>
            <Form.Item name="dstPortMax" label="Dst Port Max">
              <InputNumber min={0} max={65535} />
            </Form.Item>
          </Space>

          <Space>
            <Form.Item name="pktLenMin" label="Packet Size Min">
              <InputNumber min={0} max={65535} />
            </Form.Item>
            <Form.Item name="pktLenMax" label="Packet Size Max">
              <InputNumber min={0} max={65535} />
            </Form.Item>
          </Space>

          <Form.Item name="payloadHash" label="Payload Hash (first 4 bytes)">
            <InputNumber min={0} />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
};

export default SignaturesPage;
