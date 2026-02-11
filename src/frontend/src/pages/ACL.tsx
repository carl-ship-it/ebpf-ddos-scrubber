import React, { useState, useEffect, useCallback } from 'react';
import {
  Card,
  Table,
  Button,
  Input,
  Space,
  Tabs,
  message,
  Popconfirm,
  Tag,
  Typography,
} from 'antd';
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import * as api from '../api/client';
import type { ACLEntry } from '../types';

const { Text } = Typography;

const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

const ACLPage: React.FC = () => {
  const [blacklist, setBlacklist] = useState<ACLEntry[]>([]);
  const [whitelist, setWhitelist] = useState<ACLEntry[]>([]);
  const [newCidr, setNewCidr] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('blacklist');

  const fetchLists = useCallback(async () => {
    setLoading(true);
    try {
      const [bl, wl] = await Promise.all([
        api.getBlacklist(),
        api.getWhitelist(),
      ]);
      setBlacklist(bl);
      setWhitelist(wl);
    } catch {
      // API may not be available yet
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLists();
  }, [fetchLists]);

  const handleAdd = async () => {
    const cidr = newCidr.trim();
    if (!cidr || !cidrRegex.test(cidr)) {
      message.error('Invalid CIDR format (e.g. 10.0.0.0/8 or 192.168.1.1)');
      return;
    }
    try {
      if (activeTab === 'blacklist') {
        await api.addBlacklist(cidr);
        message.success(`Added ${cidr} to blacklist`);
      } else {
        await api.addWhitelist(cidr);
        message.success(`Added ${cidr} to whitelist`);
      }
      setNewCidr('');
      fetchLists();
    } catch (err) {
      message.error(`Failed to add: ${err}`);
    }
  };

  const handleRemove = async (cidr: string, list: 'blacklist' | 'whitelist') => {
    try {
      if (list === 'blacklist') {
        await api.removeBlacklist(cidr);
      } else {
        await api.removeWhitelist(cidr);
      }
      message.success(`Removed ${cidr}`);
      fetchLists();
    } catch (err) {
      message.error(`Failed to remove: ${err}`);
    }
  };

  const makeColumns = (list: 'blacklist' | 'whitelist'): ColumnsType<ACLEntry> => [
    {
      title: 'CIDR',
      dataIndex: 'cidr',
      key: 'cidr',
      render: (cidr: string) => <Text code>{cidr}</Text>,
    },
    ...(list === 'blacklist'
      ? [
          {
            title: 'Reason',
            dataIndex: 'reason',
            key: 'reason',
            width: 120,
            render: (r: number) => <Tag color="red">code {r}</Tag>,
          },
        ]
      : []),
    {
      title: 'Action',
      key: 'action',
      width: 100,
      render: (_: unknown, record: ACLEntry) => (
        <Popconfirm
          title={`Remove ${record.cidr}?`}
          onConfirm={() => handleRemove(record.cidr, list)}
        >
          <Button type="text" danger icon={<DeleteOutlined />} size="small" />
        </Popconfirm>
      ),
    },
  ];

  const addBar = (
    <Space style={{ marginBottom: 16 }}>
      <Input
        placeholder="e.g. 10.0.0.0/8"
        value={newCidr}
        onChange={(e) => setNewCidr(e.target.value)}
        onPressEnter={handleAdd}
        style={{ width: 240 }}
      />
      <Button type="primary" icon={<PlusOutlined />} onClick={handleAdd}>
        Add to {activeTab}
      </Button>
    </Space>
  );

  return (
    <Card title="Access Control Lists">
      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'blacklist',
            label: (
              <span>
                Blacklist <Tag color="red">{blacklist.length}</Tag>
              </span>
            ),
            children: (
              <>
                {addBar}
                <Table
                  columns={makeColumns('blacklist')}
                  dataSource={blacklist}
                  rowKey="cidr"
                  size="small"
                  loading={loading}
                  pagination={{ pageSize: 20 }}
                />
              </>
            ),
          },
          {
            key: 'whitelist',
            label: (
              <span>
                Whitelist <Tag color="green">{whitelist.length}</Tag>
              </span>
            ),
            children: (
              <>
                {addBar}
                <Table
                  columns={makeColumns('whitelist')}
                  dataSource={whitelist}
                  rowKey="cidr"
                  size="small"
                  loading={loading}
                  pagination={{ pageSize: 20 }}
                />
              </>
            ),
          },
        ]}
      />
    </Card>
  );
};

export default ACLPage;
