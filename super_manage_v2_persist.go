package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	yaml "gopkg.in/yaml.v2"
)

type managedConfigWrite struct {
	path  string
	label string
	value any
}

type managedConfigBeforeImage struct {
	path    string
	data    []byte
	mode    os.FileMode
	existed bool
}

func (m *ManageV2) atomicWriteConfigs(newBase mtypes.SuperConfigV2, newEdges []*mtypes.EdgeConfigV2) error {
	writes := make([]managedConfigWrite, 0, 1+len(newEdges))
	writes = append(writes, managedConfigWrite{path: m.superFilePath(), label: "super.yaml", value: newBase})
	for _, edge := range newEdges {
		writes = append(writes, managedConfigWrite{
			path:  m.edgeFilePath(edge.NodeID),
			label: fmt.Sprintf("edge %d", edge.NodeID),
			value: *edge,
		})
	}

	beforeImages, err := captureManagedConfigBeforeImages(writes)
	if err != nil {
		return err
	}
	for _, write := range writes {
		if err := m.writeYAML(write.path, write.value); err != nil {
			writeErr := fmt.Errorf("write %s: %w", write.label, err)
			if restoreErr := restoreManagedConfigBeforeImages(beforeImages); restoreErr != nil {
				return errors.Join(writeErr, fmt.Errorf("restore managed config files: %w", restoreErr))
			}
			return writeErr
		}
	}
	return nil
}

func captureManagedConfigBeforeImages(writes []managedConfigWrite) ([]managedConfigBeforeImage, error) {
	images := make([]managedConfigBeforeImage, 0, len(writes))
	seen := make(map[string]struct{}, len(writes))
	for _, write := range writes {
		if _, ok := seen[write.path]; ok {
			continue
		}
		seen[write.path] = struct{}{}
		data, err := os.ReadFile(write.path)
		if errors.Is(err, os.ErrNotExist) {
			images = append(images, managedConfigBeforeImage{path: write.path})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("capture before-image %s: %w", write.path, err)
		}
		info, err := os.Stat(write.path)
		if err != nil {
			return nil, fmt.Errorf("stat before-image %s: %w", write.path, err)
		}
		images = append(images, managedConfigBeforeImage{
			path:    write.path,
			data:    data,
			mode:    info.Mode().Perm(),
			existed: true,
		})
	}
	return images, nil
}

func restoreManagedConfigBeforeImages(images []managedConfigBeforeImage) error {
	errs := make([]error, 0)
	for index := len(images) - 1; index >= 0; index-- {
		image := images[index]
		if !image.existed {
			if err := os.Remove(image.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove newly-created %s: %w", image.path, err))
			}
			continue
		}
		if err := atomicWriteBytes(image.path, image.data); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", image.path, err))
			continue
		}
		if err := os.Chmod(image.path, image.mode); err != nil {
			errs = append(errs, fmt.Errorf("restore mode %s: %w", image.path, err))
		}
	}
	return errors.Join(errs...)
}

func (m *ManageV2) superFilePath() string {
	return filepath.Join(m.configDir, m.superFile)
}

func (m *ManageV2) edgeFilePath(nodeID mtypes.Vertex) string {
	return filepath.Join(m.configDir, fmt.Sprintf("edge_%d.yaml", int(nodeID)))
}

func atomicWriteYAML(path string, value any) error {
	data, err := yaml.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return atomicWriteBytes(path, data)
}

func atomicWriteBytes(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := ioutil.TempFile(dir, ".tmp-*.yaml")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
