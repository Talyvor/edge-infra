package main

import (
	"context"
	"crypto/x509"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/edge-infra/control-plane/internal/xds"
)

// The client certificates the charts issue. edge-proxy's Envoys, one per
// Kubernetes node, share one; edge-egress's share another. A certificate whose
// DNS SAN is exactly a node id speaks for that node alone.
const (
	proxyClientIdentity  = "envoy-xds-client"
	egressClientIdentity = "envoy-egress-xds-client"
)

// certAllowsNode reports whether a verified client certificate may speak for
// the xDS node id: its own name, or the class of node its role serves.
// shortcut: edge-proxy nodes share one certificate, so one proxy can still claim
// another proxy's node id; issue a certificate per node to close that.
func certAllowsNode(cert *x509.Certificate, nodeID string) bool {
	if nodeID == "" {
		return false
	}
	for _, name := range cert.DNSNames {
		switch {
		case name == nodeID,
			name == proxyClientIdentity && !xds.IsEgressNode(nodeID),
			name == egressClientIdentity && xds.IsEgressNode(nodeID):
			return true
		}
	}
	return false
}

// checkNode refuses a message unless the caller's verified certificate speaks
// for the node it names.
func checkNode(ctx context.Context, node *corev3.Node) error {
	p, _ := peer.FromContext(ctx)
	var leaf *x509.Certificate
	if p != nil {
		if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.VerifiedChains) > 0 {
			leaf = ti.State.VerifiedChains[0][0]
		}
	}
	if leaf == nil {
		return status.Error(codes.Unauthenticated, "xDS needs a verified client certificate")
	}
	if !certAllowsNode(leaf, node.GetId()) {
		return status.Errorf(codes.PermissionDenied, "client certificate does not speak for node %q", node.GetId())
	}
	return nil
}

// requestNode returns the node a request names, and whether the message is one
// that names a node at all.
func requestNode(m any) (*corev3.Node, bool) {
	switch r := m.(type) {
	case *discovery.DiscoveryRequest:
		return r.GetNode(), true
	case *discovery.DeltaDiscoveryRequest:
		return r.GetNode(), true
	case *accesslogv3.StreamAccessLogsMessage:
		return r.GetIdentifier().GetNode(), true
	}
	return nil, false
}

// nodeIdentityUnary checks the fetch (unary) discovery calls.
func nodeIdentityUnary(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if node, ok := requestNode(req); ok {
		if err := checkNode(ctx, node); err != nil {
			return nil, err
		}
	}
	return handler(ctx, req)
}

// nodeIdentityStream checks every message on a discovery or decision-log stream
// before the server reads it, so a refused node never receives a snapshot.
func nodeIdentityStream(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	cs := &nodeCheckedStream{ServerStream: ss}
	err := handler(srv, cs)
	// go-control-plane ends a stream whose receive failed with OK; report why.
	if cs.refused != nil {
		return cs.refused
	}
	return err
}

type nodeCheckedStream struct {
	grpc.ServerStream
	checked bool
	refused error
}

func (s *nodeCheckedStream) RecvMsg(m any) error {
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	node, ok := requestNode(m)
	// Envoy names its node on a stream's first message only; the server keeps
	// that node for the rest, so a later message is checked only if it names one.
	if !ok || (node == nil && s.checked) {
		return nil
	}
	if err := checkNode(s.Context(), node); err != nil {
		s.refused = err
		return err
	}
	s.checked = true
	return nil
}
