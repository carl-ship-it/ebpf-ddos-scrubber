import React, { useState, useEffect } from 'react';
import {
  Card,
  Form,
  InputNumber,
  Button,
  Row,
  Col,
  Divider,
  message,
  Descriptions,
  Typography,
} from 'antd';
import { SaveOutlined, ReloadOutlined } from '@ant-design/icons';
import * as api from '../api/client';
import { useCurrentStats } from '../hooks/useStats';
import { formatPPS, formatBPS } from '../utils';
import type { RateConfig } from '../types';

const { Text } = Typography;

const RateLimitPage: React.FC = () => {
  const [form] = Form.useForm<RateConfig>();
  const [loading, setLoading] = useState(false);
  const stats = useCurrentStats();

  const fetchConfig = async () => {
    setLoading(true);
    try {
      const cfg = await api.getRateConfig();
      form.setFieldsValue(cfg);
    } catch {
      // API not available yet
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConfig();
  }, []);

  const handleSave = async () => {
    try {
      const values = await form.validateFields();
      await api.setRateConfig(values);
      message.success('Rate limits updated');
    } catch (err) {
      message.error(`Failed to update: ${err}`);
    }
  };

  return (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={14}>
        <Card title="Rate Limit Configuration">
          <Form
            form={form}
            layout="vertical"
            initialValues={{
              synRatePps: 1000,
              udpRatePps: 10000,
              icmpRatePps: 100,
              globalPpsLimit: 0,
              globalBpsLimit: 0,
            }}
          >
            <Divider orientation="left" plain>
              Per-Source Limits
            </Divider>

            <Row gutter={16}>
              <Col span={8}>
                <Form.Item
                  name="synRatePps"
                  label="SYN Rate (PPS)"
                  tooltip="Maximum SYN packets per second per source IP"
                >
                  <InputNumber min={0} max={10000000} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col span={8}>
                <Form.Item
                  name="udpRatePps"
                  label="UDP Rate (PPS)"
                  tooltip="Maximum UDP packets per second per source IP"
                >
                  <InputNumber min={0} max={10000000} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col span={8}>
                <Form.Item
                  name="icmpRatePps"
                  label="ICMP Rate (PPS)"
                  tooltip="Maximum ICMP packets per second per source IP"
                >
                  <InputNumber min={0} max={10000000} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
            </Row>

            <Divider orientation="left" plain>
              Global Limits (0 = disabled)
            </Divider>

            <Row gutter={16}>
              <Col span={12}>
                <Form.Item
                  name="globalPpsLimit"
                  label="Global PPS Limit"
                  tooltip="Maximum total packets per second across all sources"
                >
                  <InputNumber min={0} max={100000000} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item
                  name="globalBpsLimit"
                  label="Global BPS Limit"
                  tooltip="Maximum total bits per second across all sources"
                >
                  <InputNumber min={0} max={100000000000} style={{ width: '100%' }} />
                </Form.Item>
              </Col>
            </Row>

            <Form.Item>
              <Button
                type="primary"
                icon={<SaveOutlined />}
                onClick={handleSave}
                loading={loading}
              >
                Apply
              </Button>
              <Button
                icon={<ReloadOutlined />}
                onClick={fetchConfig}
                style={{ marginLeft: 8 }}
              >
                Reset
              </Button>
            </Form.Item>
          </Form>
        </Card>
      </Col>

      <Col xs={24} lg={10}>
        <Card title="Current Traffic Rates" size="small">
          <Descriptions column={1} size="small">
            <Descriptions.Item label="Inbound PPS">
              <Text strong>{stats ? formatPPS(stats.rxPps) : '--'}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Inbound BPS">
              <Text strong>{stats ? formatBPS(stats.rxBps) : '--'}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Drop PPS">
              <Text type="danger">{stats ? formatPPS(stats.dropPps) : '--'}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="Rate Limited">
              <Text type="warning">
                {stats ? stats.rateLimited.toLocaleString() : '--'}
              </Text>
            </Descriptions.Item>
          </Descriptions>
        </Card>
      </Col>
    </Row>
  );
};

export default RateLimitPage;
